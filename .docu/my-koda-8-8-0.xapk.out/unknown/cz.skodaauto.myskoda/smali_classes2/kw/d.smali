.class public final Lkw/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkw/e;


# static fields
.field public static final v:Lfv/b;


# instance fields
.field public final a:Low/b;

.field public final b:Lbc/j;

.field public final c:Lkw/f;

.field public final d:Ljava/util/List;

.field public final e:Lay0/k;

.field public final f:Ljava/util/LinkedHashMap;

.field public g:Ljava/lang/Integer;

.field public final h:Ld3/a;

.field public final i:Llw/g;

.field public final j:Ljava/util/TreeMap;

.field public k:Ljava/lang/Integer;

.field public final l:Landroid/graphics/Canvas;

.field public final m:Lb81/c;

.field public final n:Lb81/d;

.field public final o:Lh6/e;

.field public final p:Lil/g;

.field public final q:Lkw/c;

.field public final r:Landroid/graphics/RectF;

.field public final s:Ljava/util/List;

.field public final t:Ljava/util/TreeMap;

.field public u:Ljava/util/UUID;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lfv/b;

    .line 2
    .line 3
    const/16 v1, 0xd

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lfv/b;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lkw/d;->v:Lfv/b;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>([Lnw/g;Llw/q;Llw/q;Llw/m;Lbc/a;Lbc/j;Lkw/f;Ljava/util/List;Lay0/k;)V
    .locals 1

    .line 1
    const-string v0, "layers"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "getXStep"

    .line 7
    .line 8
    invoke-static {p9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p5, p0, Lkw/d;->a:Low/b;

    .line 15
    .line 16
    iput-object p6, p0, Lkw/d;->b:Lbc/j;

    .line 17
    .line 18
    iput-object p7, p0, Lkw/d;->c:Lkw/f;

    .line 19
    .line 20
    iput-object p8, p0, Lkw/d;->d:Ljava/util/List;

    .line 21
    .line 22
    iput-object p9, p0, Lkw/d;->e:Lay0/k;

    .line 23
    .line 24
    new-instance p5, Ljava/util/LinkedHashMap;

    .line 25
    .line 26
    invoke-direct {p5}, Ljava/util/LinkedHashMap;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object p5, p0, Lkw/d;->f:Ljava/util/LinkedHashMap;

    .line 30
    .line 31
    new-instance p5, Ld3/a;

    .line 32
    .line 33
    const/4 p6, 0x2

    .line 34
    invoke-direct {p5, p6}, Ld3/a;-><init>(I)V

    .line 35
    .line 36
    .line 37
    iput-object p5, p0, Lkw/d;->h:Ld3/a;

    .line 38
    .line 39
    new-instance p5, Llw/g;

    .line 40
    .line 41
    invoke-direct {p5}, Llw/g;-><init>()V

    .line 42
    .line 43
    .line 44
    iput-object p5, p0, Lkw/d;->i:Llw/g;

    .line 45
    .line 46
    const/4 p6, 0x0

    .line 47
    new-array p7, p6, [Llx0/l;

    .line 48
    .line 49
    new-instance p8, Ljava/util/TreeMap;

    .line 50
    .line 51
    invoke-direct {p8}, Ljava/util/TreeMap;-><init>()V

    .line 52
    .line 53
    .line 54
    invoke-static {p8, p7}, Lmx0/x;->r(Ljava/util/AbstractMap;[Llx0/l;)V

    .line 55
    .line 56
    .line 57
    iput-object p8, p0, Lkw/d;->j:Ljava/util/TreeMap;

    .line 58
    .line 59
    new-instance p7, Landroid/graphics/Canvas;

    .line 60
    .line 61
    invoke-direct {p7}, Landroid/graphics/Canvas;-><init>()V

    .line 62
    .line 63
    .line 64
    iput-object p7, p0, Lkw/d;->l:Landroid/graphics/Canvas;

    .line 65
    .line 66
    new-instance p7, Lb81/c;

    .line 67
    .line 68
    invoke-direct {p7, p0}, Lb81/c;-><init>(Lkw/d;)V

    .line 69
    .line 70
    .line 71
    iput-object p7, p0, Lkw/d;->m:Lb81/c;

    .line 72
    .line 73
    new-instance p7, Lb81/d;

    .line 74
    .line 75
    const/16 p9, 0xc

    .line 76
    .line 77
    const/4 v0, 0x0

    .line 78
    invoke-direct {p7, p9, v0}, Lb81/d;-><init>(IZ)V

    .line 79
    .line 80
    .line 81
    iput-object p7, p0, Lkw/d;->n:Lb81/d;

    .line 82
    .line 83
    new-instance p7, Lh6/e;

    .line 84
    .line 85
    const/16 p9, 0xe

    .line 86
    .line 87
    invoke-direct {p7, p9}, Lh6/e;-><init>(I)V

    .line 88
    .line 89
    .line 90
    iput-object p7, p0, Lkw/d;->o:Lh6/e;

    .line 91
    .line 92
    new-instance p7, Lil/g;

    .line 93
    .line 94
    const/16 p9, 0xa

    .line 95
    .line 96
    invoke-direct {p7, p9, v0}, Lil/g;-><init>(IZ)V

    .line 97
    .line 98
    .line 99
    iput-object p7, p0, Lkw/d;->p:Lil/g;

    .line 100
    .line 101
    new-instance p7, Lkw/c;

    .line 102
    .line 103
    invoke-direct {p7}, Ljava/lang/Object;-><init>()V

    .line 104
    .line 105
    .line 106
    iput-object p7, p0, Lkw/d;->q:Lkw/c;

    .line 107
    .line 108
    new-instance p7, Landroid/graphics/RectF;

    .line 109
    .line 110
    invoke-direct {p7}, Landroid/graphics/RectF;-><init>()V

    .line 111
    .line 112
    .line 113
    iput-object p7, p0, Lkw/d;->r:Landroid/graphics/RectF;

    .line 114
    .line 115
    invoke-static {p1}, Lmx0/n;->b0([Ljava/lang/Object;)Ljava/util/List;

    .line 116
    .line 117
    .line 118
    move-result-object p1

    .line 119
    iput-object p1, p0, Lkw/d;->s:Ljava/util/List;

    .line 120
    .line 121
    iput-object p8, p0, Lkw/d;->t:Ljava/util/TreeMap;

    .line 122
    .line 123
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 124
    .line 125
    .line 126
    move-result-object p1

    .line 127
    const-string p7, "randomUUID(...)"

    .line 128
    .line 129
    invoke-static {p1, p7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    iput-object p1, p0, Lkw/d;->u:Ljava/util/UUID;

    .line 133
    .line 134
    sget-object p0, Llw/g;->f:[Lhy0/z;

    .line 135
    .line 136
    aget-object p1, p0, p6

    .line 137
    .line 138
    iget-object p6, p5, Llw/g;->b:Llw/k;

    .line 139
    .line 140
    invoke-virtual {p6, p5, p1, p2}, Llw/k;->setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    const/4 p1, 0x1

    .line 144
    aget-object p1, p0, p1

    .line 145
    .line 146
    iget-object p2, p5, Llw/g;->c:Llw/k;

    .line 147
    .line 148
    const/4 p6, 0x0

    .line 149
    invoke-virtual {p2, p5, p1, p6}, Llw/k;->setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V

    .line 150
    .line 151
    .line 152
    const/4 p1, 0x2

    .line 153
    aget-object p1, p0, p1

    .line 154
    .line 155
    iget-object p2, p5, Llw/g;->d:Llw/k;

    .line 156
    .line 157
    invoke-virtual {p2, p5, p1, p3}, Llw/k;->setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    const/4 p1, 0x3

    .line 161
    aget-object p0, p0, p1

    .line 162
    .line 163
    iget-object p1, p5, Llw/g;->e:Llw/k;

    .line 164
    .line 165
    invoke-virtual {p1, p5, p0, p4}, Llw/k;->setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V

    .line 166
    .line 167
    .line 168
    return-void
.end method


# virtual methods
.method public final a(Lkw/g;Lkw/i;Ljava/lang/Object;Ld3/a;)V
    .locals 1

    .line 1
    check-cast p3, Lmw/a;

    .line 2
    .line 3
    const-string v0, "horizontalDimensions"

    .line 4
    .line 5
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v0, "model"

    .line 9
    .line 10
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-string p3, "insets"

    .line 14
    .line 15
    invoke-static {p4, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-interface {p1}, Lkw/g;->g()Lmw/a;

    .line 19
    .line 20
    .line 21
    move-result-object p3

    .line 22
    iget-object v0, p0, Lkw/d;->p:Lil/g;

    .line 23
    .line 24
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    iput-object p1, v0, Lil/g;->e:Ljava/lang/Object;

    .line 28
    .line 29
    iput-object p2, v0, Lil/g;->f:Ljava/lang/Object;

    .line 30
    .line 31
    iput-object p4, v0, Lil/g;->g:Ljava/lang/Object;

    .line 32
    .line 33
    invoke-virtual {p0, p3, v0}, Lkw/d;->c(Lmw/a;Lkw/b;)V

    .line 34
    .line 35
    .line 36
    return-void
.end method

.method public final b(Lkw/g;FLjava/lang/Object;Ld3/a;)V
    .locals 1

    .line 1
    check-cast p3, Lmw/a;

    .line 2
    .line 3
    const-string v0, "model"

    .line 4
    .line 5
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string p3, "insets"

    .line 9
    .line 10
    invoke-static {p4, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-interface {p1}, Lkw/g;->g()Lmw/a;

    .line 14
    .line 15
    .line 16
    move-result-object p3

    .line 17
    iget-object v0, p0, Lkw/d;->q:Lkw/c;

    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    iput-object p1, v0, Lkw/c;->d:Lkw/g;

    .line 23
    .line 24
    iput p2, v0, Lkw/c;->e:F

    .line 25
    .line 26
    iput-object p4, v0, Lkw/c;->f:Ld3/a;

    .line 27
    .line 28
    invoke-virtual {p0, p3, v0}, Lkw/d;->c(Lmw/a;Lkw/b;)V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public final c(Lmw/a;Lkw/b;)V
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "consumer"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p1, p1, Lmw/a;->a:Ljava/util/List;

    .line 12
    .line 13
    check-cast p1, Ljava/util/Collection;

    .line 14
    .line 15
    invoke-static {p1}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    iget-object p0, p0, Lkw/d;->s:Ljava/util/List;

    .line 20
    .line 21
    check-cast p0, Ljava/lang/Iterable;

    .line 22
    .line 23
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_4

    .line 32
    .line 33
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    check-cast v0, Lnw/g;

    .line 38
    .line 39
    instance-of v1, v0, Lnw/g;

    .line 40
    .line 41
    if-eqz v1, :cond_3

    .line 42
    .line 43
    new-instance v1, Ljava/util/ArrayList;

    .line 44
    .line 45
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    :cond_1
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    if-eqz v3, :cond_2

    .line 57
    .line 58
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v3

    .line 62
    instance-of v4, v3, Lmw/j;

    .line 63
    .line 64
    if-eqz v4, :cond_1

    .line 65
    .line 66
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_2
    invoke-static {v1}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    check-cast v1, Lmw/j;

    .line 75
    .line 76
    invoke-interface {p2, v1, v0}, Lkw/b;->q(Lmw/j;Lnw/g;)V

    .line 77
    .line 78
    .line 79
    if-eqz v1, :cond_0

    .line 80
    .line 81
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 86
    .line 87
    const-string p1, "Unexpected `CartesianLayer` implementation."

    .line 88
    .line 89
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    throw p0

    .line 93
    :cond_4
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-eq p0, p1, :cond_1

    .line 2
    .line 3
    instance-of v0, p1, Lkw/d;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Lkw/d;->u:Ljava/util/UUID;

    .line 8
    .line 9
    check-cast p1, Lkw/d;

    .line 10
    .line 11
    iget-object v1, p1, Lkw/d;->u:Ljava/util/UUID;

    .line 12
    .line 13
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    iget-object v0, p0, Lkw/d;->a:Low/b;

    .line 20
    .line 21
    iget-object v1, p1, Lkw/d;->a:Low/b;

    .line 22
    .line 23
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    iget-object v0, p0, Lkw/d;->b:Lbc/j;

    .line 30
    .line 31
    iget-object v1, p1, Lkw/d;->b:Lbc/j;

    .line 32
    .line 33
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_0

    .line 38
    .line 39
    iget-object v0, p0, Lkw/d;->c:Lkw/f;

    .line 40
    .line 41
    iget-object v1, p1, Lkw/d;->c:Lkw/f;

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Lkw/f;->equals(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    if-eqz v0, :cond_0

    .line 48
    .line 49
    iget-object v0, p0, Lkw/d;->d:Ljava/util/List;

    .line 50
    .line 51
    iget-object v1, p1, Lkw/d;->d:Ljava/util/List;

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-eqz v0, :cond_0

    .line 58
    .line 59
    iget-object v0, p0, Lkw/d;->e:Lay0/k;

    .line 60
    .line 61
    iget-object v1, p1, Lkw/d;->e:Lay0/k;

    .line 62
    .line 63
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    if-eqz v0, :cond_0

    .line 68
    .line 69
    iget-object p0, p0, Lkw/d;->s:Ljava/util/List;

    .line 70
    .line 71
    iget-object p1, p1, Lkw/d;->s:Ljava/util/List;

    .line 72
    .line 73
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result p0

    .line 77
    if-eqz p0, :cond_0

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_0
    const/4 p0, 0x0

    .line 81
    return p0

    .line 82
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 83
    return p0
.end method

.method public final hashCode()I
    .locals 10

    .line 1
    iget-object v0, p0, Lkw/d;->u:Ljava/util/UUID;

    .line 2
    .line 3
    iget-object v8, p0, Lkw/d;->e:Lay0/k;

    .line 4
    .line 5
    iget-object v9, p0, Lkw/d;->s:Ljava/util/List;

    .line 6
    .line 7
    iget-object v1, p0, Lkw/d;->a:Low/b;

    .line 8
    .line 9
    iget-object v2, p0, Lkw/d;->b:Lbc/j;

    .line 10
    .line 11
    iget-object v3, p0, Lkw/d;->c:Lkw/f;

    .line 12
    .line 13
    const/4 v4, 0x0

    .line 14
    const/4 v5, 0x0

    .line 15
    iget-object v6, p0, Lkw/d;->d:Ljava/util/List;

    .line 16
    .line 17
    const/4 v7, 0x0

    .line 18
    filled-new-array/range {v0 .. v9}, [Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-static {p0}, Ljava/util/Objects;->hash([Ljava/lang/Object;)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0
.end method
