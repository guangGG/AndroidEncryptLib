package gapp.season.encryptlib;

import android.text.TextUtils;

import java.util.List;
import java.util.Map;
import java.util.Set;

public class ElUtil {
    public static String removeBlank(String str) {
        if (!TextUtils.isEmpty(str)) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < str.length(); i++) {
                char c = str.charAt(i);
                if (c > ' ') {
                    sb.append(c);
                }
            }
            return sb.toString();
        }
        return str;
    }

    public static <E> boolean isEmpty(E[] array) {
        if (array == null) {
            return true;
        }
        return array.length == 0;
    }

    public static <E> boolean isEmpty(List<E> list) {
        if (list == null) {
            return true;
        }
        return list.size() == 0;
    }

    public static <E> boolean isEmpty(Set<E> set) {
        if (set == null) {
            return true;
        }
        return set.size() == 0;
    }

    public static <K, V> boolean isEmpty(Map<K, V> map) {
        if (map == null) {
            return true;
        }
        return map.size() == 0;
    }

    public static <E> boolean isContains(E[] array, E element) {
        if (!isEmpty(array)) {
            for (E e : array) {
                if (e == element) {
                    return true;
                }
                if (e != null && e.equals(element)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static <E> boolean isContains(List<E> list, E element) {
        if (!isEmpty(list)) {
            return list.contains(element);
        }
        return false;
    }

    public static <E> boolean isContains(Set<E> set, E element) {
        if (!isEmpty(set)) {
            return set.contains(element);
        }
        return false;
    }

    public static <K, V> boolean isContainsKey(Map<K, V> map, K key) {
        if (!isEmpty(map)) {
            return isContains(map.keySet(), key);
        }
        return false;
    }

    public static <K, V> boolean isContainsValue(Map<K, V> map, V value) {
        if (!isEmpty(map)) {
            for (Map.Entry<K, V> entry : map.entrySet()) {
                if (entry != null) {
                    V v = entry.getValue();
                    if (v == value) {
                        return true;
                    }
                    if (v != null && v.equals(value)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
