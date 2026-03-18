.class public final Ltm/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk4/l;


# instance fields
.field public final a:Lt1/j0;

.field public final b:I

.field public final c:Lk4/x;


# direct methods
.method public constructor <init>(Landroid/graphics/Typeface;)V
    .locals 11

    .line 1
    const-string v0, "typeface"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lt1/j0;

    .line 7
    .line 8
    invoke-direct {v0, p1}, Lt1/j0;-><init>(Landroid/graphics/Typeface;)V

    .line 9
    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    new-array v2, v1, [Lk4/v;

    .line 13
    .line 14
    new-instance v3, Ljava/util/LinkedHashMap;

    .line 15
    .line 16
    invoke-direct {v3}, Ljava/util/LinkedHashMap;-><init>()V

    .line 17
    .line 18
    .line 19
    array-length v4, v2

    .line 20
    if-gtz v4, :cond_3

    .line 21
    .line 22
    new-instance v2, Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v3}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    if-eqz v4, :cond_1

    .line 40
    .line 41
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v4

    .line 45
    check-cast v4, Ljava/util/Map$Entry;

    .line 46
    .line 47
    invoke-interface {v4}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v5

    .line 51
    check-cast v5, Ljava/lang/String;

    .line 52
    .line 53
    invoke-interface {v4}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v4

    .line 57
    check-cast v4, Ljava/util/List;

    .line 58
    .line 59
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 60
    .line 61
    .line 62
    move-result v6

    .line 63
    const/4 v7, 0x1

    .line 64
    if-ne v6, v7, :cond_0

    .line 65
    .line 66
    check-cast v4, Ljava/lang/Iterable;

    .line 67
    .line 68
    invoke-static {v4, v2}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 69
    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_0
    const-string p0, "\'"

    .line 73
    .line 74
    const-string p1, "\' must be unique. Actual [ ["

    .line 75
    .line 76
    invoke-static {p0, v5, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    move-object v5, v4

    .line 81
    check-cast v5, Ljava/lang/Iterable;

    .line 82
    .line 83
    const/4 v9, 0x0

    .line 84
    const/16 v10, 0x3f

    .line 85
    .line 86
    const/4 v6, 0x0

    .line 87
    const/4 v7, 0x0

    .line 88
    const/4 v8, 0x0

    .line 89
    invoke-static/range {v5 .. v10}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p1

    .line 93
    const/16 v0, 0x5d

    .line 94
    .line 95
    invoke-static {p0, p1, v0}, La7/g0;->j(Ljava/lang/StringBuilder;Ljava/lang/String;C)Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 100
    .line 101
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    throw p1

    .line 109
    :cond_1
    new-instance v3, Ljava/util/ArrayList;

    .line 110
    .line 111
    invoke-direct {v3, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 112
    .line 113
    .line 114
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 115
    .line 116
    .line 117
    move-result v2

    .line 118
    if-gtz v2, :cond_2

    .line 119
    .line 120
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 121
    .line 122
    .line 123
    iput-object v0, p0, Ltm/k;->a:Lt1/j0;

    .line 124
    .line 125
    invoke-virtual {p1}, Landroid/graphics/Typeface;->isItalic()Z

    .line 126
    .line 127
    .line 128
    move-result v0

    .line 129
    iput v0, p0, Ltm/k;->b:I

    .line 130
    .line 131
    new-instance v0, Lk4/x;

    .line 132
    .line 133
    invoke-virtual {p1}, Landroid/graphics/Typeface;->getWeight()I

    .line 134
    .line 135
    .line 136
    move-result p1

    .line 137
    invoke-direct {v0, p1}, Lk4/x;-><init>(I)V

    .line 138
    .line 139
    .line 140
    iput-object v0, p0, Ltm/k;->c:Lk4/x;

    .line 141
    .line 142
    return-void

    .line 143
    :cond_2
    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 148
    .line 149
    .line 150
    new-instance p0, Ljava/lang/ClassCastException;

    .line 151
    .line 152
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 153
    .line 154
    .line 155
    throw p0

    .line 156
    :cond_3
    aget-object p0, v2, v1

    .line 157
    .line 158
    const/4 p0, 0x0

    .line 159
    throw p0
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final b()Lk4/x;
    .locals 0

    .line 1
    iget-object p0, p0, Ltm/k;->c:Lk4/x;

    .line 2
    .line 3
    return-object p0
.end method

.method public final c()I
    .locals 0

    .line 1
    iget p0, p0, Ltm/k;->b:I

    .line 2
    .line 3
    return p0
.end method
