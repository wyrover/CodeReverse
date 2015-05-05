#ifndef CODEREVERSE_H_
#define CODEREVERSE_H_

////////////////////////////////////////////////////////////////////////////
// CodeReverse.h
// Copyright (C) 2013-2015 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////
// LOLONG, HILONG, MAKELONGLONG

#ifndef LOLONG
    #define LOLONG(dwl) static_cast<DWORD>(dwl)
#endif
#ifndef HILONG
    #define HILONG(dwl) static_cast<DWORD>(((dwl) >> 32) & 0xFFFFFFFF)
#endif
#ifndef MAKELONGLONG
    #define MAKELONGLONG(lo,hi) \
        ((static_cast<DWORDLONG>(hi) << 32) | static_cast<DWORD>(lo))
#endif

////////////////////////////////////////////////////////////////////////////
// CR_Addr32, CR_Addr64 (virtual address)

typedef unsigned long       CR_Addr32;
typedef unsigned long long  CR_Addr64;

////////////////////////////////////////////////////////////////////////////
// CR_Range -- closed range

struct CR_Range {
public:
    typedef unsigned long long value_type;
    static const value_type npos = 0x7FFFFFFF;
    value_type m_min, m_max;

public:
    CR_Range() : m_min(0), m_max(CR_Range::npos) { }

    CR_Range(value_type mi, value_type ma) : m_min(mi), m_max(ma) { }

    CR_Range(const CR_Range& range) :
        m_min(range.m_min), m_max(range.m_max) { }

    value_type& Min() { return m_min; }
    value_type& Max() { return m_max; }
    const value_type& Min() const { return m_min; }
    const value_type& Max() const { return m_max; }

    bool empty() const {
        return m_max < m_min;
    }
    bool whole() const {
        return m_min == 0 && m_max == CR_Range::npos;
    }

    void clear() {
        m_min = 0;
        m_max = CR_Range::npos;
    }

    void LimitMin(value_type m) {
        if (m_min < m) {
            m_min = m;
        }
    }

    void LimitMax(value_type m) {
        if (m_max > m) {
            m_max = m;
        }
    }

    void Set(value_type value) {
        m_min = m_max = value;
    }

    std::string str() const {
        std::string ret;
        if (whole()) {
            ret = "(whole)";
        } else {
            ret += "[";
            ret += std::to_string(Min());
            ret += ", ";
            if (Max() != CR_Range::npos) {
                ret += std::to_string(Max());
            } else {
                ret += "npos";
            }
            ret += "]";
        }
        return ret;
    }
};

////////////////////////////////////////////////////////////////////////////
// CR_VecSet<ITEM_T> -- vector and set

template <typename ITEM_T>
class CR_VecSet : public std::vector<ITEM_T> {
public:
    typedef typename std::vector<ITEM_T>::iterator iterator;
    typedef typename std::vector<ITEM_T>::const_iterator const_iterator;

public:
    CR_VecSet() { }

    CR_VecSet(const CR_VecSet<ITEM_T>& vs) : std::vector<ITEM_T>(vs)
    { }

    CR_VecSet<ITEM_T>& operator=(const CR_VecSet<ITEM_T>& vs) {
        this->assign(vs.begin(), vs.end());
        return *this;
    }

    virtual ~CR_VecSet() { }

    std::size_t insert(const ITEM_T& item) {
        this->push_back(item);
        return this->size() - 1;
    }

    template <class T_IT2>
    iterator insert(const_iterator it1, T_IT2 first, T_IT2 last) {
        return std::vector<ITEM_T>::insert(it1, first, last);
    }

    template <class T_IT2>
    void assign(T_IT2 first, T_IT2 last) {
        std::vector<ITEM_T>::assign(first, last);
    }

    bool Contains(const ITEM_T& item) const {
        const std::size_t siz = this->size();
        for (std::size_t i = 0; i < siz; i++) {
            if (this->at(i) == item)
                return true;
        }
        return false;
    }

    std::size_t Find(const ITEM_T& item) const {
        const std::size_t siz = this->size();
        for (std::size_t i = 0; i < siz; i++) {
            if (this->at(i) == item)
                return i;
        }
        return static_cast<std::size_t>(-1);
    }

    std::size_t AddUnique(const ITEM_T& item) {
        const std::size_t siz = this->size();
        for (std::size_t i = 0; i < siz; i++) {
            if (this->at(i) == item)
                return i;
        }
        this->push_back(item);
        return this->size() - 1;
    }

    void AddHead(const CR_VecSet<ITEM_T>& items) {
        std::vector<ITEM_T>::insert(
            std::vector<ITEM_T>::begin(), items.begin(), items.end());
    }

    void AddTail(const CR_VecSet<ITEM_T>& items) {
        std::vector<ITEM_T>::insert(
            std::vector<ITEM_T>::end(), items.begin(), items.end());
    }

    std::size_t count(const ITEM_T& item) const {
        std::size_t count = 0;
        for (std::size_t i : *this) {
            if (this->at(i) == item)
                count++;
        }
        return count;
    }

    void sort() {
        std::sort(this->begin(), this->end());
    }

    void unique() {
        std::unique(this->begin(), this->end());
    }

    void erase(const ITEM_T& item) {
        std::size_t i, j;
        const std::size_t count = this->size();
        for (i = j = 0; i < count; i++) {
            if (this->at(i) != item) {
                this->at(j++) = this->at(i);
            }
        }
        if (i != j)
            this->resize(j);
    }
}; // class CR_VecSet<ITEM_T>

namespace std {
    template <typename ITEM_T>
    inline void swap(CR_VecSet<ITEM_T>& vs1, CR_VecSet<ITEM_T>& vs2) {
        vs1.swap(vs2);
    }
}

////////////////////////////////////////////////////////////////////////////
// CR_Addr32Set, CR_Addr64Set

typedef std::unordered_set<CR_Addr32> CR_Addr32Set;
typedef std::unordered_set<CR_Addr64> CR_Addr64Set;

////////////////////////////////////////////////////////////////////////////
// CR_Strings

typedef CR_VecSet<std::string> CR_Strings;

////////////////////////////////////////////////////////////////////////////
// CR_DataBytes

typedef std::vector<BYTE> CR_DataBytes;

////////////////////////////////////////////////////////////////////////////
// CR_ErrorInfo

class CR_ErrorInfo {
public:
    typedef CR_Strings error_container;
    enum Type {
        NOTHING = 0, NOTICE, WARN, ERR
    };

public:
    CR_ErrorInfo() { }

    void add_message(Type type, const CR_Location& location,
                     const std::string str)
    {
        switch (type) {
        case NOTICE:    add_notice(location, str); break;
        case WARN:      add_warning(location, str); break;
        case ERR:       add_error(location, str); break;
        default: break;
        }
    }

    void add_notice(const CR_Location& location, const std::string str) {
        m_notices.emplace_back(location.str() + ": " + str);
    }

    void add_warning(const CR_Location& location, const std::string str) {
        m_warnings.emplace_back(location.str() + ": WARNING: " + str);
    }

    void add_error(const CR_Location& location, const std::string str) {
        m_errors.emplace_back(location.str() + ": ERROR: " + str);
    }

    void add_notice(const std::string str) {
        m_notices.emplace_back(str);
    }

    void add_warning(const std::string str) {
        m_warnings.emplace_back("WARNING: " + str);
    }

    void add_error(const std::string str) {
        m_errors.emplace_back("ERROR: " + str);
    }

          error_container& notices()        { return m_notices; }
    const error_container& notices() const  { return m_notices; }
          error_container& warnings()       { return m_warnings; }
    const error_container& warnings() const { return m_warnings; }
          error_container& errors()         { return m_errors; }
    const error_container& errors() const   { return m_errors; }

    void emit_all(std::FILE *fp = stderr) {
        for (auto& e : errors()) {
            fprintf(fp, "%s\n", e.c_str());
        }
        for (auto& w : warnings()) {
            fprintf(fp, "%s\n", w.c_str());
        }
        for (auto& n : notices()) {
            fprintf(fp, "%s\n", n.c_str());
        }
    }

    void clear_notices()    { m_notices.clear(); }
    void clear_warnings()   { m_warnings.clear(); }
    void clear_errors()     { m_errors.clear(); }

    void clear() {
        m_notices.clear();
        m_warnings.clear();
        m_errors.clear();
    }

protected:
    error_container m_notices;
    error_container m_warnings;
    error_container m_errors;
};

////////////////////////////////////////////////////////////////////////////

// inline functions
#include "CodeReverse_inl.h"

#endif  // ndef CODEREVERSE_H_
