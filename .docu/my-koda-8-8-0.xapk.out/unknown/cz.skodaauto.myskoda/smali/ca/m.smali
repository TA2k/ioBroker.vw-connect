.class public final Lca/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv9/a0;


# instance fields
.field public d:I

.field public final e:Ljava/lang/Object;

.field public final f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;

.field public h:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 110
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 111
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lca/m;->e:Ljava/lang/Object;

    .line 112
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lca/m;->f:Ljava/lang/Object;

    .line 113
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lca/m;->g:Ljava/lang/Object;

    .line 114
    sget-object v0, Lg11/g;->r:Ljava/util/LinkedHashSet;

    .line 115
    iput-object v0, p0, Lca/m;->h:Ljava/lang/Object;

    const/4 v0, 0x1

    .line 116
    iput v0, p0, Lca/m;->d:I

    return-void
.end method

.method public constructor <init>(Lca/m;)V
    .locals 6

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    iget-object v0, p1, Lca/m;->e:Ljava/lang/Object;

    check-cast v0, Ljava/util/ArrayList;

    .line 11
    iget-object v1, p1, Lca/m;->h:Ljava/lang/Object;

    check-cast v1, Ljava/util/LinkedHashSet;

    .line 12
    sget-object v2, Lg11/g;->r:Ljava/util/LinkedHashSet;

    .line 13
    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 14
    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 15
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Class;

    .line 16
    sget-object v3, Lg11/g;->s:Ljava/util/Map;

    invoke-interface {v3, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    .line 17
    :cond_0
    iput-object v2, p0, Lca/m;->e:Ljava/lang/Object;

    .line 18
    new-instance v0, La61/a;

    const/16 v1, 0x8

    .line 19
    invoke-direct {v0, v1}, La61/a;-><init>(I)V

    .line 20
    iput-object v0, p0, Lca/m;->g:Ljava/lang/Object;

    .line 21
    iget-object v0, p1, Lca/m;->g:Ljava/lang/Object;

    check-cast v0, Ljava/util/ArrayList;

    .line 22
    iput-object v0, p0, Lca/m;->h:Ljava/lang/Object;

    .line 23
    iget-object v0, p1, Lca/m;->f:Ljava/lang/Object;

    check-cast v0, Ljava/util/ArrayList;

    .line 24
    iput-object v0, p0, Lca/m;->f:Ljava/lang/Object;

    .line 25
    iget p1, p1, Lca/m;->d:I

    .line 26
    iput p1, p0, Lca/m;->d:I

    .line 27
    new-instance p0, Ljava/util/LinkedHashMap;

    invoke-direct {p0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 28
    new-instance p0, Ljava/util/HashMap;

    invoke-direct {p0}, Ljava/util/HashMap;-><init>()V

    .line 29
    new-instance p1, Lh11/a;

    const/16 v1, 0x2a

    .line 30
    invoke-direct {p1, v1}, Lh11/a;-><init>(C)V

    .line 31
    new-instance v1, Lh11/a;

    const/16 v2, 0x5f

    .line 32
    invoke-direct {v1, v2}, Lh11/a;-><init>(C)V

    const/4 v2, 0x2

    .line 33
    new-array v3, v2, [Lm11/a;

    const/4 v4, 0x0

    aput-object p1, v3, v4

    const/4 p1, 0x1

    aput-object v1, v3, p1

    invoke-static {v3}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v1

    invoke-static {v1, p0}, Lg11/l;->b(Ljava/lang/Iterable;Ljava/util/HashMap;)V

    .line 34
    invoke-static {v0, p0}, Lg11/l;->b(Ljava/lang/Iterable;Ljava/util/HashMap;)V

    .line 35
    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    const/16 v1, 0x5c

    .line 36
    invoke-static {v1}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    move-result-object v1

    new-instance v3, Lh11/c;

    .line 37
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 38
    invoke-static {v3}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v3

    invoke-virtual {v0, v1, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/16 v1, 0x60

    .line 39
    invoke-static {v1}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    move-result-object v1

    new-instance v3, Lh11/d;

    .line 40
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 41
    invoke-static {v3}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v3

    invoke-virtual {v0, v1, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/16 v1, 0x26

    .line 42
    invoke-static {v1}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    move-result-object v1

    new-instance v3, Lh11/e;

    .line 43
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 44
    invoke-static {v3}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v3

    invoke-virtual {v0, v1, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/16 v1, 0x3c

    .line 45
    invoke-static {v1}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    move-result-object v1

    new-instance v3, Lh11/b;

    .line 46
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 47
    new-instance v5, Lh11/f;

    .line 48
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 49
    new-array v2, v2, [Lh11/g;

    aput-object v3, v2, v4

    aput-object v5, v2, p1

    invoke-static {v2}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    invoke-virtual {v0, v1, p1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    invoke-virtual {p0}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    move-result-object p0

    invoke-virtual {v0}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    move-result-object p1

    .line 51
    new-instance v0, Ljava/util/BitSet;

    invoke-direct {v0}, Ljava/util/BitSet;-><init>()V

    .line 52
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Character;

    .line 53
    invoke-virtual {v1}, Ljava/lang/Character;->charValue()C

    move-result v1

    invoke-virtual {v0, v1}, Ljava/util/BitSet;->set(I)V

    goto :goto_1

    .line 54
    :cond_1
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result p1

    if-eqz p1, :cond_2

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Character;

    .line 55
    invoke-virtual {p1}, Ljava/lang/Character;->charValue()C

    move-result p1

    invoke-virtual {v0, p1}, Ljava/util/BitSet;->set(I)V

    goto :goto_2

    :cond_2
    const/16 p0, 0x5b

    .line 56
    invoke-virtual {v0, p0}, Ljava/util/BitSet;->set(I)V

    const/16 p0, 0x5d

    .line 57
    invoke-virtual {v0, p0}, Ljava/util/BitSet;->set(I)V

    const/16 p0, 0x21

    .line 58
    invoke-virtual {v0, p0}, Ljava/util/BitSet;->set(I)V

    const/16 p0, 0xa

    .line 59
    invoke-virtual {v0, p0}, Ljava/util/BitSet;->set(I)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;)V
    .locals 13

    .line 60
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 61
    invoke-static {}, Landroid/opengl/GLES20;->glCreateProgram()I

    move-result v0

    iput v0, p0, Lca/m;->d:I

    .line 62
    invoke-static {}, Lw7/a;->e()V

    const v1, 0x8b31

    .line 63
    invoke-static {v0, v1, p1}, Lca/m;->c(IILjava/lang/String;)V

    const p1, 0x8b30

    .line 64
    invoke-static {v0, p1, p2}, Lca/m;->c(IILjava/lang/String;)V

    .line 65
    invoke-static {v0}, Landroid/opengl/GLES20;->glLinkProgram(I)V

    const/4 p1, 0x0

    .line 66
    filled-new-array {p1}, [I

    move-result-object p2

    const v1, 0x8b82

    .line 67
    invoke-static {v0, v1, p2, p1}, Landroid/opengl/GLES20;->glGetProgramiv(II[II)V

    .line 68
    aget p2, p2, p1

    const/4 v1, 0x1

    if-ne p2, v1, :cond_0

    move p2, v1

    goto :goto_0

    :cond_0
    move p2, p1

    :goto_0
    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Unable to link shader program: \n"

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 69
    invoke-static {v0}, Landroid/opengl/GLES20;->glGetProgramInfoLog(I)Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    .line 70
    invoke-static {v2, p2}, Lw7/a;->f(Ljava/lang/String;Z)V

    .line 71
    invoke-static {v0}, Landroid/opengl/GLES20;->glUseProgram(I)V

    .line 72
    new-instance p2, Ljava/util/HashMap;

    invoke-direct {p2}, Ljava/util/HashMap;-><init>()V

    iput-object p2, p0, Lca/m;->g:Ljava/lang/Object;

    .line 73
    new-array p2, v1, [I

    const v2, 0x8b89

    .line 74
    invoke-static {v0, v2, p2, p1}, Landroid/opengl/GLES20;->glGetProgramiv(II[II)V

    .line 75
    aget v0, p2, p1

    new-array v0, v0, [Lgv/a;

    iput-object v0, p0, Lca/m;->e:Ljava/lang/Object;

    move v3, p1

    .line 76
    :goto_1
    aget v0, p2, p1

    if-ge v3, v0, :cond_3

    .line 77
    iget v2, p0, Lca/m;->d:I

    .line 78
    new-array v0, v1, [I

    const v4, 0x8b8a

    .line 79
    invoke-static {v2, v4, v0, p1}, Landroid/opengl/GLES20;->glGetProgramiv(II[II)V

    .line 80
    aget v4, v0, p1

    new-array v11, v4, [B

    .line 81
    new-array v5, v1, [I

    new-array v7, v1, [I

    new-array v9, v1, [I

    const/4 v10, 0x0

    const/4 v12, 0x0

    const/4 v6, 0x0

    const/4 v8, 0x0

    invoke-static/range {v2 .. v12}, Landroid/opengl/GLES20;->glGetActiveAttrib(III[II[II[II[BI)V

    .line 82
    new-instance v0, Ljava/lang/String;

    move v5, p1

    :goto_2
    if-ge v5, v4, :cond_2

    .line 83
    aget-byte v6, v11, v5

    if-nez v6, :cond_1

    move v4, v5

    goto :goto_3

    :cond_1
    add-int/lit8 v5, v5, 0x1

    goto :goto_2

    .line 84
    :cond_2
    :goto_3
    invoke-direct {v0, v11, p1, v4}, Ljava/lang/String;-><init>([BII)V

    .line 85
    invoke-static {v2, v0}, Landroid/opengl/GLES20;->glGetAttribLocation(ILjava/lang/String;)I

    .line 86
    new-instance v2, Lgv/a;

    const/16 v4, 0x19

    .line 87
    invoke-direct {v2, v4}, Lgv/a;-><init>(I)V

    .line 88
    iget-object v4, p0, Lca/m;->e:Ljava/lang/Object;

    check-cast v4, [Lgv/a;

    aput-object v2, v4, v3

    .line 89
    iget-object v4, p0, Lca/m;->g:Ljava/lang/Object;

    check-cast v4, Ljava/util/HashMap;

    invoke-virtual {v4, v0, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    add-int/lit8 v3, v3, 0x1

    goto :goto_1

    .line 90
    :cond_3
    new-instance p2, Ljava/util/HashMap;

    invoke-direct {p2}, Ljava/util/HashMap;-><init>()V

    iput-object p2, p0, Lca/m;->h:Ljava/lang/Object;

    .line 91
    new-array p2, v1, [I

    .line 92
    iget v0, p0, Lca/m;->d:I

    const v2, 0x8b86

    invoke-static {v0, v2, p2, p1}, Landroid/opengl/GLES20;->glGetProgramiv(II[II)V

    .line 93
    aget v0, p2, p1

    new-array v0, v0, [Lip/v;

    iput-object v0, p0, Lca/m;->f:Ljava/lang/Object;

    move v3, p1

    .line 94
    :goto_4
    aget v0, p2, p1

    if-ge v3, v0, :cond_6

    .line 95
    iget v2, p0, Lca/m;->d:I

    .line 96
    new-array v0, v1, [I

    const v4, 0x8b87

    .line 97
    invoke-static {v2, v4, v0, p1}, Landroid/opengl/GLES20;->glGetProgramiv(II[II)V

    .line 98
    new-array v9, v1, [I

    .line 99
    aget v4, v0, p1

    new-array v11, v4, [B

    .line 100
    new-array v5, v1, [I

    new-array v7, v1, [I

    const/4 v10, 0x0

    const/4 v12, 0x0

    const/4 v6, 0x0

    const/4 v8, 0x0

    invoke-static/range {v2 .. v12}, Landroid/opengl/GLES20;->glGetActiveUniform(III[II[II[II[BI)V

    .line 101
    new-instance v0, Ljava/lang/String;

    move v5, p1

    :goto_5
    if-ge v5, v4, :cond_5

    .line 102
    aget-byte v6, v11, v5

    if-nez v6, :cond_4

    move v4, v5

    goto :goto_6

    :cond_4
    add-int/lit8 v5, v5, 0x1

    goto :goto_5

    .line 103
    :cond_5
    :goto_6
    invoke-direct {v0, v11, p1, v4}, Ljava/lang/String;-><init>([BII)V

    .line 104
    invoke-static {v2, v0}, Landroid/opengl/GLES20;->glGetUniformLocation(ILjava/lang/String;)I

    .line 105
    new-instance v2, Lip/v;

    const/16 v4, 0x19

    .line 106
    invoke-direct {v2, v4}, Lip/v;-><init>(I)V

    .line 107
    iget-object v4, p0, Lca/m;->f:Ljava/lang/Object;

    check-cast v4, [Lip/v;

    aput-object v2, v4, v3

    .line 108
    iget-object v4, p0, Lca/m;->h:Ljava/lang/Object;

    check-cast v4, Ljava/util/HashMap;

    invoke-virtual {v4, v0, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    add-int/lit8 v3, v3, 0x1

    goto :goto_4

    .line 109
    :cond_6
    invoke-static {}, Lw7/a;->e()V

    return-void
.end method

.method public constructor <init>(Ln1/g;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lca/m;->e:Ljava/lang/Object;

    .line 2
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    new-instance v0, Ln1/r;

    const/4 v1, 0x0

    .line 3
    invoke-direct {v0, v1, v1}, Ln1/r;-><init>(II)V

    .line 4
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iput-object p1, p0, Lca/m;->f:Ljava/lang/Object;

    .line 5
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lca/m;->g:Ljava/lang/Object;

    .line 6
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    iput-object p1, p0, Lca/m;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lo8/a0;Lhu/q;[B[La8/t1;I)V
    .locals 0

    .line 117
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 118
    iput-object p1, p0, Lca/m;->e:Ljava/lang/Object;

    .line 119
    iput-object p2, p0, Lca/m;->f:Ljava/lang/Object;

    .line 120
    iput-object p3, p0, Lca/m;->g:Ljava/lang/Object;

    .line 121
    iput-object p4, p0, Lca/m;->h:Ljava/lang/Object;

    .line 122
    iput p5, p0, Lca/m;->d:I

    return-void
.end method

.method public constructor <init>(Lv9/d0;I)V
    .locals 2

    .line 123
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lca/m;->h:Ljava/lang/Object;

    .line 124
    new-instance p1, Lm9/f;

    const/4 v0, 0x5

    new-array v1, v0, [B

    .line 125
    invoke-direct {p1, v0, v1}, Lm9/f;-><init>(I[B)V

    .line 126
    iput-object p1, p0, Lca/m;->e:Ljava/lang/Object;

    .line 127
    new-instance p1, Landroid/util/SparseArray;

    invoke-direct {p1}, Landroid/util/SparseArray;-><init>()V

    iput-object p1, p0, Lca/m;->f:Ljava/lang/Object;

    .line 128
    new-instance p1, Landroid/util/SparseIntArray;

    invoke-direct {p1}, Landroid/util/SparseIntArray;-><init>()V

    iput-object p1, p0, Lca/m;->g:Ljava/lang/Object;

    .line 129
    iput p2, p0, Lca/m;->d:I

    return-void
.end method

.method public constructor <init>(Lz9/v;)V
    .locals 1

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lca/m;->e:Ljava/lang/Object;

    .line 8
    new-instance p1, Landroidx/collection/b1;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Landroidx/collection/b1;-><init>(I)V

    iput-object p1, p0, Lca/m;->f:Ljava/lang/Object;

    return-void
.end method

.method public static c(IILjava/lang/String;)V
    .locals 3

    .line 1
    invoke-static {p1}, Landroid/opengl/GLES20;->glCreateShader(I)I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    invoke-static {p1, p2}, Landroid/opengl/GLES20;->glShaderSource(ILjava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-static {p1}, Landroid/opengl/GLES20;->glCompileShader(I)V

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    filled-new-array {v0}, [I

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    const v2, 0x8b81

    .line 17
    .line 18
    .line 19
    invoke-static {p1, v2, v1, v0}, Landroid/opengl/GLES20;->glGetShaderiv(II[II)V

    .line 20
    .line 21
    .line 22
    aget v1, v1, v0

    .line 23
    .line 24
    const/4 v2, 0x1

    .line 25
    if-ne v1, v2, :cond_0

    .line 26
    .line 27
    move v0, v2

    .line 28
    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 29
    .line 30
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 31
    .line 32
    .line 33
    invoke-static {p1}, Landroid/opengl/GLES20;->glGetShaderInfoLog(I)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string v2, ", source: \n"

    .line 41
    .line 42
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p2

    .line 52
    invoke-static {p2, v0}, Lw7/a;->f(Ljava/lang/String;Z)V

    .line 53
    .line 54
    .line 55
    invoke-static {p0, p1}, Landroid/opengl/GLES20;->glAttachShader(II)V

    .line 56
    .line 57
    .line 58
    invoke-static {p1}, Landroid/opengl/GLES20;->glDeleteShader(I)V

    .line 59
    .line 60
    .line 61
    invoke-static {}, Lw7/a;->e()V

    .line 62
    .line 63
    .line 64
    return-void
.end method


# virtual methods
.method public a(Lw7/u;Lo8/q;Lh11/h;)V
    .locals 0

    .line 1
    return-void
.end method

.method public b(Lw7/p;)V
    .locals 32

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lca/m;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Landroid/util/SparseArray;

    .line 8
    .line 9
    iget-object v3, v0, Lca/m;->g:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v3, Landroid/util/SparseIntArray;

    .line 12
    .line 13
    iget-object v4, v0, Lca/m;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v4, Lm9/f;

    .line 16
    .line 17
    iget-object v5, v0, Lca/m;->h:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v5, Lv9/d0;

    .line 20
    .line 21
    iget-object v6, v5, Lv9/d0;->g:Landroid/util/SparseArray;

    .line 22
    .line 23
    iget-object v7, v5, Lv9/d0;->h:Landroid/util/SparseBooleanArray;

    .line 24
    .line 25
    invoke-virtual {v1}, Lw7/p;->w()I

    .line 26
    .line 27
    .line 28
    move-result v8

    .line 29
    const/4 v9, 0x2

    .line 30
    if-eq v8, v9, :cond_0

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    iget-object v8, v5, Lv9/d0;->b:Ljava/util/List;

    .line 34
    .line 35
    const/4 v10, 0x0

    .line 36
    invoke-interface {v8, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v8

    .line 40
    check-cast v8, Lw7/u;

    .line 41
    .line 42
    invoke-virtual {v1}, Lw7/p;->w()I

    .line 43
    .line 44
    .line 45
    move-result v11

    .line 46
    and-int/lit16 v11, v11, 0x80

    .line 47
    .line 48
    if-nez v11, :cond_1

    .line 49
    .line 50
    :goto_0
    return-void

    .line 51
    :cond_1
    const/4 v11, 0x1

    .line 52
    invoke-virtual {v1, v11}, Lw7/p;->J(I)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v1}, Lw7/p;->C()I

    .line 56
    .line 57
    .line 58
    move-result v12

    .line 59
    const/4 v13, 0x3

    .line 60
    invoke-virtual {v1, v13}, Lw7/p;->J(I)V

    .line 61
    .line 62
    .line 63
    iget-object v14, v4, Lm9/f;->b:[B

    .line 64
    .line 65
    invoke-virtual {v1, v14, v10, v9}, Lw7/p;->h([BII)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {v4, v10}, Lm9/f;->q(I)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v4, v13}, Lm9/f;->t(I)V

    .line 72
    .line 73
    .line 74
    const/16 v14, 0xd

    .line 75
    .line 76
    invoke-virtual {v4, v14}, Lm9/f;->i(I)I

    .line 77
    .line 78
    .line 79
    move-result v15

    .line 80
    iput v15, v5, Lv9/d0;->q:I

    .line 81
    .line 82
    iget-object v15, v4, Lm9/f;->b:[B

    .line 83
    .line 84
    invoke-virtual {v1, v15, v10, v9}, Lw7/p;->h([BII)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v4, v10}, Lm9/f;->q(I)V

    .line 88
    .line 89
    .line 90
    const/4 v15, 0x4

    .line 91
    invoke-virtual {v4, v15}, Lm9/f;->t(I)V

    .line 92
    .line 93
    .line 94
    const/16 v11, 0xc

    .line 95
    .line 96
    invoke-virtual {v4, v11}, Lm9/f;->i(I)I

    .line 97
    .line 98
    .line 99
    move-result v9

    .line 100
    invoke-virtual {v1, v9}, Lw7/p;->J(I)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {v2}, Landroid/util/SparseArray;->clear()V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v3}, Landroid/util/SparseIntArray;->clear()V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v1}, Lw7/p;->a()I

    .line 110
    .line 111
    .line 112
    move-result v9

    .line 113
    :goto_1
    if-lez v9, :cond_21

    .line 114
    .line 115
    iget-object v11, v4, Lm9/f;->b:[B

    .line 116
    .line 117
    const/4 v15, 0x5

    .line 118
    invoke-virtual {v1, v11, v10, v15}, Lw7/p;->h([BII)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v4, v10}, Lm9/f;->q(I)V

    .line 122
    .line 123
    .line 124
    const/16 v11, 0x8

    .line 125
    .line 126
    invoke-virtual {v4, v11}, Lm9/f;->i(I)I

    .line 127
    .line 128
    .line 129
    move-result v11

    .line 130
    invoke-virtual {v4, v13}, Lm9/f;->t(I)V

    .line 131
    .line 132
    .line 133
    invoke-virtual {v4, v14}, Lm9/f;->i(I)I

    .line 134
    .line 135
    .line 136
    move-result v10

    .line 137
    const/4 v14, 0x4

    .line 138
    invoke-virtual {v4, v14}, Lm9/f;->t(I)V

    .line 139
    .line 140
    .line 141
    const/16 v14, 0xc

    .line 142
    .line 143
    invoke-virtual {v4, v14}, Lm9/f;->i(I)I

    .line 144
    .line 145
    .line 146
    move-result v16

    .line 147
    iget v14, v1, Lw7/p;->b:I

    .line 148
    .line 149
    add-int v13, v14, v16

    .line 150
    .line 151
    const/16 v17, 0x0

    .line 152
    .line 153
    const/16 v18, -0x1

    .line 154
    .line 155
    move-object/from16 v21, v17

    .line 156
    .line 157
    move-object/from16 v23, v21

    .line 158
    .line 159
    move/from16 v20, v18

    .line 160
    .line 161
    const/16 v22, 0x0

    .line 162
    .line 163
    :goto_2
    iget v15, v1, Lw7/p;->b:I

    .line 164
    .line 165
    move-object/from16 v25, v4

    .line 166
    .line 167
    if-ge v15, v13, :cond_2

    .line 168
    .line 169
    invoke-virtual {v1}, Lw7/p;->w()I

    .line 170
    .line 171
    .line 172
    move-result v15

    .line 173
    invoke-virtual {v1}, Lw7/p;->w()I

    .line 174
    .line 175
    .line 176
    move-result v19

    .line 177
    iget v4, v1, Lw7/p;->b:I

    .line 178
    .line 179
    add-int v4, v4, v19

    .line 180
    .line 181
    if-le v4, v13, :cond_3

    .line 182
    .line 183
    :cond_2
    move-object/from16 v31, v6

    .line 184
    .line 185
    move/from16 v30, v9

    .line 186
    .line 187
    goto/16 :goto_7

    .line 188
    .line 189
    :cond_3
    const/16 v19, 0x87

    .line 190
    .line 191
    const/16 v24, 0x81

    .line 192
    .line 193
    move/from16 v30, v9

    .line 194
    .line 195
    const/4 v9, 0x5

    .line 196
    if-ne v15, v9, :cond_8

    .line 197
    .line 198
    invoke-virtual {v1}, Lw7/p;->y()J

    .line 199
    .line 200
    .line 201
    move-result-wide v26

    .line 202
    const-wide/32 v28, 0x41432d33

    .line 203
    .line 204
    .line 205
    cmp-long v9, v26, v28

    .line 206
    .line 207
    if-nez v9, :cond_4

    .line 208
    .line 209
    move/from16 v20, v24

    .line 210
    .line 211
    goto :goto_4

    .line 212
    :cond_4
    const-wide/32 v28, 0x45414333

    .line 213
    .line 214
    .line 215
    cmp-long v9, v26, v28

    .line 216
    .line 217
    if-nez v9, :cond_5

    .line 218
    .line 219
    move/from16 v20, v19

    .line 220
    .line 221
    goto :goto_4

    .line 222
    :cond_5
    const-wide/32 v28, 0x41432d34

    .line 223
    .line 224
    .line 225
    cmp-long v9, v26, v28

    .line 226
    .line 227
    if-nez v9, :cond_6

    .line 228
    .line 229
    :goto_3
    const/16 v20, 0xac

    .line 230
    .line 231
    goto :goto_4

    .line 232
    :cond_6
    const-wide/32 v28, 0x48455643

    .line 233
    .line 234
    .line 235
    cmp-long v9, v26, v28

    .line 236
    .line 237
    if-nez v9, :cond_7

    .line 238
    .line 239
    const/16 v20, 0x24

    .line 240
    .line 241
    :cond_7
    :goto_4
    move/from16 v19, v4

    .line 242
    .line 243
    move-object/from16 v31, v6

    .line 244
    .line 245
    goto/16 :goto_6

    .line 246
    .line 247
    :cond_8
    const/16 v9, 0x6a

    .line 248
    .line 249
    if-ne v15, v9, :cond_9

    .line 250
    .line 251
    move/from16 v19, v4

    .line 252
    .line 253
    move-object/from16 v31, v6

    .line 254
    .line 255
    move/from16 v20, v24

    .line 256
    .line 257
    goto/16 :goto_6

    .line 258
    .line 259
    :cond_9
    const/16 v9, 0x7a

    .line 260
    .line 261
    if-ne v15, v9, :cond_a

    .line 262
    .line 263
    move-object/from16 v31, v6

    .line 264
    .line 265
    move/from16 v20, v19

    .line 266
    .line 267
    move/from16 v19, v4

    .line 268
    .line 269
    goto/16 :goto_6

    .line 270
    .line 271
    :cond_a
    const/16 v9, 0x7f

    .line 272
    .line 273
    if-ne v15, v9, :cond_d

    .line 274
    .line 275
    invoke-virtual {v1}, Lw7/p;->w()I

    .line 276
    .line 277
    .line 278
    move-result v9

    .line 279
    const/16 v15, 0x15

    .line 280
    .line 281
    if-ne v9, v15, :cond_b

    .line 282
    .line 283
    goto :goto_3

    .line 284
    :cond_b
    const/16 v15, 0xe

    .line 285
    .line 286
    if-ne v9, v15, :cond_c

    .line 287
    .line 288
    const/16 v20, 0x88

    .line 289
    .line 290
    goto :goto_4

    .line 291
    :cond_c
    const/16 v15, 0x21

    .line 292
    .line 293
    if-ne v9, v15, :cond_7

    .line 294
    .line 295
    const/16 v20, 0x8b

    .line 296
    .line 297
    goto :goto_4

    .line 298
    :cond_d
    const/16 v9, 0x7b

    .line 299
    .line 300
    if-ne v15, v9, :cond_e

    .line 301
    .line 302
    move/from16 v19, v4

    .line 303
    .line 304
    move-object/from16 v31, v6

    .line 305
    .line 306
    const/16 v20, 0x8a

    .line 307
    .line 308
    goto :goto_6

    .line 309
    :cond_e
    const/16 v9, 0xa

    .line 310
    .line 311
    if-ne v15, v9, :cond_f

    .line 312
    .line 313
    sget-object v9, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 314
    .line 315
    const/4 v15, 0x3

    .line 316
    invoke-virtual {v1, v15, v9}, Lw7/p;->u(ILjava/nio/charset/Charset;)Ljava/lang/String;

    .line 317
    .line 318
    .line 319
    move-result-object v9

    .line 320
    invoke-virtual {v9}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 321
    .line 322
    .line 323
    move-result-object v21

    .line 324
    invoke-virtual {v1}, Lw7/p;->w()I

    .line 325
    .line 326
    .line 327
    move-result v9

    .line 328
    move/from16 v19, v4

    .line 329
    .line 330
    move-object/from16 v31, v6

    .line 331
    .line 332
    move/from16 v22, v9

    .line 333
    .line 334
    goto :goto_6

    .line 335
    :cond_f
    const/4 v0, 0x3

    .line 336
    const/16 v9, 0x59

    .line 337
    .line 338
    if-ne v15, v9, :cond_11

    .line 339
    .line 340
    new-instance v9, Ljava/util/ArrayList;

    .line 341
    .line 342
    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 343
    .line 344
    .line 345
    :goto_5
    iget v15, v1, Lw7/p;->b:I

    .line 346
    .line 347
    if-ge v15, v4, :cond_10

    .line 348
    .line 349
    sget-object v15, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 350
    .line 351
    invoke-virtual {v1, v0, v15}, Lw7/p;->u(ILjava/nio/charset/Charset;)Ljava/lang/String;

    .line 352
    .line 353
    .line 354
    move-result-object v15

    .line 355
    invoke-virtual {v15}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 356
    .line 357
    .line 358
    move-result-object v0

    .line 359
    invoke-virtual {v1}, Lw7/p;->w()I

    .line 360
    .line 361
    .line 362
    move/from16 v19, v4

    .line 363
    .line 364
    const/4 v15, 0x4

    .line 365
    new-array v4, v15, [B

    .line 366
    .line 367
    move-object/from16 v31, v6

    .line 368
    .line 369
    const/4 v6, 0x0

    .line 370
    invoke-virtual {v1, v4, v6, v15}, Lw7/p;->h([BII)V

    .line 371
    .line 372
    .line 373
    new-instance v6, Lv9/e0;

    .line 374
    .line 375
    invoke-direct {v6, v0, v4}, Lv9/e0;-><init>(Ljava/lang/String;[B)V

    .line 376
    .line 377
    .line 378
    invoke-virtual {v9, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 379
    .line 380
    .line 381
    move/from16 v4, v19

    .line 382
    .line 383
    move-object/from16 v6, v31

    .line 384
    .line 385
    const/4 v0, 0x3

    .line 386
    goto :goto_5

    .line 387
    :cond_10
    move/from16 v19, v4

    .line 388
    .line 389
    move-object/from16 v31, v6

    .line 390
    .line 391
    move-object/from16 v23, v9

    .line 392
    .line 393
    const/16 v20, 0x59

    .line 394
    .line 395
    goto :goto_6

    .line 396
    :cond_11
    move/from16 v19, v4

    .line 397
    .line 398
    move-object/from16 v31, v6

    .line 399
    .line 400
    const/16 v0, 0x6f

    .line 401
    .line 402
    if-ne v15, v0, :cond_12

    .line 403
    .line 404
    const/16 v20, 0x101

    .line 405
    .line 406
    :cond_12
    :goto_6
    iget v0, v1, Lw7/p;->b:I

    .line 407
    .line 408
    sub-int v4, v19, v0

    .line 409
    .line 410
    invoke-virtual {v1, v4}, Lw7/p;->J(I)V

    .line 411
    .line 412
    .line 413
    move-object/from16 v0, p0

    .line 414
    .line 415
    move-object/from16 v4, v25

    .line 416
    .line 417
    move/from16 v9, v30

    .line 418
    .line 419
    move-object/from16 v6, v31

    .line 420
    .line 421
    goto/16 :goto_2

    .line 422
    .line 423
    :goto_7
    invoke-virtual {v1, v13}, Lw7/p;->I(I)V

    .line 424
    .line 425
    .line 426
    new-instance v19, Lbb/g0;

    .line 427
    .line 428
    iget-object v0, v1, Lw7/p;->a:[B

    .line 429
    .line 430
    invoke-static {v0, v14, v13}, Ljava/util/Arrays;->copyOfRange([BII)[B

    .line 431
    .line 432
    .line 433
    move-result-object v24

    .line 434
    invoke-direct/range {v19 .. v24}, Lbb/g0;-><init>(ILjava/lang/String;ILjava/util/ArrayList;[B)V

    .line 435
    .line 436
    .line 437
    move-object/from16 v4, v19

    .line 438
    .line 439
    move-object/from16 v0, v21

    .line 440
    .line 441
    const/4 v6, 0x6

    .line 442
    if-eq v11, v6, :cond_13

    .line 443
    .line 444
    const/4 v9, 0x5

    .line 445
    if-ne v11, v9, :cond_14

    .line 446
    .line 447
    :cond_13
    move/from16 v11, v20

    .line 448
    .line 449
    :cond_14
    add-int/lit8 v16, v16, 0x5

    .line 450
    .line 451
    sub-int v9, v30, v16

    .line 452
    .line 453
    invoke-virtual {v7, v10}, Landroid/util/SparseBooleanArray;->get(I)Z

    .line 454
    .line 455
    .line 456
    move-result v6

    .line 457
    if-eqz v6, :cond_15

    .line 458
    .line 459
    const/4 v15, 0x3

    .line 460
    goto/16 :goto_a

    .line 461
    .line 462
    :cond_15
    iget-object v6, v5, Lv9/d0;->e:Laq/m;

    .line 463
    .line 464
    const-string v13, "video/mp2t"

    .line 465
    .line 466
    const/4 v14, 0x2

    .line 467
    const/4 v15, 0x3

    .line 468
    if-eq v11, v14, :cond_20

    .line 469
    .line 470
    if-eq v11, v15, :cond_1f

    .line 471
    .line 472
    const/4 v14, 0x4

    .line 473
    if-eq v11, v14, :cond_1f

    .line 474
    .line 475
    const/16 v14, 0x15

    .line 476
    .line 477
    if-eq v11, v14, :cond_1e

    .line 478
    .line 479
    const/16 v14, 0x1b

    .line 480
    .line 481
    if-eq v11, v14, :cond_1d

    .line 482
    .line 483
    const/16 v14, 0x24

    .line 484
    .line 485
    if-eq v11, v14, :cond_1c

    .line 486
    .line 487
    const/16 v14, 0x2d

    .line 488
    .line 489
    if-eq v11, v14, :cond_1b

    .line 490
    .line 491
    const/16 v14, 0x59

    .line 492
    .line 493
    if-eq v11, v14, :cond_1a

    .line 494
    .line 495
    const/16 v14, 0xac

    .line 496
    .line 497
    if-eq v11, v14, :cond_19

    .line 498
    .line 499
    const/16 v14, 0x101

    .line 500
    .line 501
    if-eq v11, v14, :cond_18

    .line 502
    .line 503
    const/16 v14, 0x8a

    .line 504
    .line 505
    if-eq v11, v14, :cond_17

    .line 506
    .line 507
    const/16 v14, 0x8b

    .line 508
    .line 509
    if-eq v11, v14, :cond_16

    .line 510
    .line 511
    packed-switch v11, :pswitch_data_0

    .line 512
    .line 513
    .line 514
    packed-switch v11, :pswitch_data_1

    .line 515
    .line 516
    .line 517
    packed-switch v11, :pswitch_data_2

    .line 518
    .line 519
    .line 520
    :pswitch_0
    move-object/from16 v0, v17

    .line 521
    .line 522
    goto/16 :goto_9

    .line 523
    .line 524
    :pswitch_1
    new-instance v0, Lv9/b0;

    .line 525
    .line 526
    new-instance v4, Lrn/i;

    .line 527
    .line 528
    const-string v6, "application/x-scte35"

    .line 529
    .line 530
    invoke-direct {v4, v6}, Lrn/i;-><init>(Ljava/lang/String;)V

    .line 531
    .line 532
    .line 533
    invoke-direct {v0, v4}, Lv9/b0;-><init>(Lv9/a0;)V

    .line 534
    .line 535
    .line 536
    goto/16 :goto_9

    .line 537
    .line 538
    :pswitch_2
    new-instance v6, Lv9/w;

    .line 539
    .line 540
    new-instance v11, Lv9/b;

    .line 541
    .line 542
    invoke-virtual {v4}, Lbb/g0;->m()I

    .line 543
    .line 544
    .line 545
    move-result v4

    .line 546
    const/4 v14, 0x0

    .line 547
    invoke-direct {v11, v0, v13, v4, v14}, Lv9/b;-><init>(Ljava/lang/String;Ljava/lang/String;II)V

    .line 548
    .line 549
    .line 550
    invoke-direct {v6, v11}, Lv9/w;-><init>(Lv9/h;)V

    .line 551
    .line 552
    .line 553
    :goto_8
    move-object v0, v6

    .line 554
    goto/16 :goto_9

    .line 555
    .line 556
    :pswitch_3
    new-instance v6, Lv9/w;

    .line 557
    .line 558
    new-instance v11, Lv9/s;

    .line 559
    .line 560
    invoke-virtual {v4}, Lbb/g0;->m()I

    .line 561
    .line 562
    .line 563
    move-result v4

    .line 564
    invoke-direct {v11, v0, v4}, Lv9/s;-><init>(Ljava/lang/String;I)V

    .line 565
    .line 566
    .line 567
    invoke-direct {v6, v11}, Lv9/w;-><init>(Lv9/h;)V

    .line 568
    .line 569
    .line 570
    goto :goto_8

    .line 571
    :pswitch_4
    new-instance v0, Lv9/w;

    .line 572
    .line 573
    new-instance v11, Lv9/m;

    .line 574
    .line 575
    new-instance v13, Lv9/c0;

    .line 576
    .line 577
    invoke-virtual {v6, v4}, Laq/m;->a(Lbb/g0;)Ljava/util/List;

    .line 578
    .line 579
    .line 580
    move-result-object v4

    .line 581
    const/4 v6, 0x1

    .line 582
    invoke-direct {v13, v4, v6}, Lv9/c0;-><init>(Ljava/util/List;I)V

    .line 583
    .line 584
    .line 585
    invoke-direct {v11, v13}, Lv9/m;-><init>(Lv9/c0;)V

    .line 586
    .line 587
    .line 588
    invoke-direct {v0, v11}, Lv9/w;-><init>(Lv9/h;)V

    .line 589
    .line 590
    .line 591
    goto/16 :goto_9

    .line 592
    .line 593
    :pswitch_5
    new-instance v6, Lv9/w;

    .line 594
    .line 595
    new-instance v11, Lv9/e;

    .line 596
    .line 597
    invoke-virtual {v4}, Lbb/g0;->m()I

    .line 598
    .line 599
    .line 600
    move-result v4

    .line 601
    const/4 v14, 0x0

    .line 602
    invoke-direct {v11, v0, v4, v13, v14}, Lv9/e;-><init>(Ljava/lang/String;ILjava/lang/String;Z)V

    .line 603
    .line 604
    .line 605
    invoke-direct {v6, v11}, Lv9/w;-><init>(Lv9/h;)V

    .line 606
    .line 607
    .line 608
    goto :goto_8

    .line 609
    :cond_16
    new-instance v6, Lv9/w;

    .line 610
    .line 611
    new-instance v11, Lv9/f;

    .line 612
    .line 613
    invoke-virtual {v4}, Lbb/g0;->m()I

    .line 614
    .line 615
    .line 616
    move-result v4

    .line 617
    const/16 v13, 0x1520

    .line 618
    .line 619
    invoke-direct {v11, v0, v4, v13}, Lv9/f;-><init>(Ljava/lang/String;II)V

    .line 620
    .line 621
    .line 622
    invoke-direct {v6, v11}, Lv9/w;-><init>(Lv9/h;)V

    .line 623
    .line 624
    .line 625
    goto :goto_8

    .line 626
    :cond_17
    :pswitch_6
    new-instance v6, Lv9/w;

    .line 627
    .line 628
    new-instance v11, Lv9/f;

    .line 629
    .line 630
    invoke-virtual {v4}, Lbb/g0;->m()I

    .line 631
    .line 632
    .line 633
    move-result v4

    .line 634
    const/16 v13, 0x1000

    .line 635
    .line 636
    invoke-direct {v11, v0, v4, v13}, Lv9/f;-><init>(Ljava/lang/String;II)V

    .line 637
    .line 638
    .line 639
    invoke-direct {v6, v11}, Lv9/w;-><init>(Lv9/h;)V

    .line 640
    .line 641
    .line 642
    goto :goto_8

    .line 643
    :cond_18
    new-instance v0, Lv9/b0;

    .line 644
    .line 645
    new-instance v4, Lrn/i;

    .line 646
    .line 647
    const-string v6, "application/vnd.dvb.ait"

    .line 648
    .line 649
    invoke-direct {v4, v6}, Lrn/i;-><init>(Ljava/lang/String;)V

    .line 650
    .line 651
    .line 652
    invoke-direct {v0, v4}, Lv9/b0;-><init>(Lv9/a0;)V

    .line 653
    .line 654
    .line 655
    goto/16 :goto_9

    .line 656
    .line 657
    :cond_19
    new-instance v6, Lv9/w;

    .line 658
    .line 659
    new-instance v11, Lv9/b;

    .line 660
    .line 661
    invoke-virtual {v4}, Lbb/g0;->m()I

    .line 662
    .line 663
    .line 664
    move-result v4

    .line 665
    const/4 v14, 0x1

    .line 666
    invoke-direct {v11, v0, v13, v4, v14}, Lv9/b;-><init>(Ljava/lang/String;Ljava/lang/String;II)V

    .line 667
    .line 668
    .line 669
    invoke-direct {v6, v11}, Lv9/w;-><init>(Lv9/h;)V

    .line 670
    .line 671
    .line 672
    goto :goto_8

    .line 673
    :cond_1a
    new-instance v0, Lv9/w;

    .line 674
    .line 675
    new-instance v6, Lv9/g;

    .line 676
    .line 677
    iget-object v4, v4, Lbb/g0;->f:Ljava/lang/Object;

    .line 678
    .line 679
    check-cast v4, Ljava/util/List;

    .line 680
    .line 681
    invoke-direct {v6, v4}, Lv9/g;-><init>(Ljava/util/List;)V

    .line 682
    .line 683
    .line 684
    invoke-direct {v0, v6}, Lv9/w;-><init>(Lv9/h;)V

    .line 685
    .line 686
    .line 687
    goto :goto_9

    .line 688
    :cond_1b
    new-instance v0, Lv9/w;

    .line 689
    .line 690
    new-instance v4, Lv9/u;

    .line 691
    .line 692
    invoke-direct {v4}, Lv9/u;-><init>()V

    .line 693
    .line 694
    .line 695
    invoke-direct {v0, v4}, Lv9/w;-><init>(Lv9/h;)V

    .line 696
    .line 697
    .line 698
    goto :goto_9

    .line 699
    :cond_1c
    new-instance v0, Lv9/w;

    .line 700
    .line 701
    new-instance v11, Lv9/r;

    .line 702
    .line 703
    new-instance v13, Lv9/c0;

    .line 704
    .line 705
    invoke-virtual {v6, v4}, Laq/m;->a(Lbb/g0;)Ljava/util/List;

    .line 706
    .line 707
    .line 708
    move-result-object v4

    .line 709
    const/4 v6, 0x0

    .line 710
    invoke-direct {v13, v4, v6}, Lv9/c0;-><init>(Ljava/util/List;I)V

    .line 711
    .line 712
    .line 713
    invoke-direct {v11, v13}, Lv9/r;-><init>(Lv9/c0;)V

    .line 714
    .line 715
    .line 716
    invoke-direct {v0, v11}, Lv9/w;-><init>(Lv9/h;)V

    .line 717
    .line 718
    .line 719
    goto :goto_9

    .line 720
    :cond_1d
    new-instance v0, Lv9/w;

    .line 721
    .line 722
    new-instance v11, Lv9/p;

    .line 723
    .line 724
    new-instance v13, Lv9/c0;

    .line 725
    .line 726
    invoke-virtual {v6, v4}, Laq/m;->a(Lbb/g0;)Ljava/util/List;

    .line 727
    .line 728
    .line 729
    move-result-object v4

    .line 730
    const/4 v6, 0x0

    .line 731
    invoke-direct {v13, v4, v6}, Lv9/c0;-><init>(Ljava/util/List;I)V

    .line 732
    .line 733
    .line 734
    const/4 v14, 0x0

    .line 735
    invoke-direct {v11, v13, v14, v14}, Lv9/p;-><init>(Lv9/c0;ZZ)V

    .line 736
    .line 737
    .line 738
    invoke-direct {v0, v11}, Lv9/w;-><init>(Lv9/h;)V

    .line 739
    .line 740
    .line 741
    goto :goto_9

    .line 742
    :cond_1e
    new-instance v0, Lv9/w;

    .line 743
    .line 744
    new-instance v4, Lv9/g;

    .line 745
    .line 746
    invoke-direct {v4}, Lv9/g;-><init>()V

    .line 747
    .line 748
    .line 749
    invoke-direct {v0, v4}, Lv9/w;-><init>(Lv9/h;)V

    .line 750
    .line 751
    .line 752
    goto :goto_9

    .line 753
    :cond_1f
    new-instance v6, Lv9/w;

    .line 754
    .line 755
    new-instance v11, Lv9/t;

    .line 756
    .line 757
    invoke-virtual {v4}, Lbb/g0;->m()I

    .line 758
    .line 759
    .line 760
    move-result v4

    .line 761
    invoke-direct {v11, v0, v4, v13}, Lv9/t;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 762
    .line 763
    .line 764
    invoke-direct {v6, v11}, Lv9/w;-><init>(Lv9/h;)V

    .line 765
    .line 766
    .line 767
    goto/16 :goto_8

    .line 768
    .line 769
    :cond_20
    :pswitch_7
    new-instance v0, Lv9/w;

    .line 770
    .line 771
    new-instance v11, Lv9/j;

    .line 772
    .line 773
    new-instance v14, Lv9/c0;

    .line 774
    .line 775
    invoke-virtual {v6, v4}, Laq/m;->a(Lbb/g0;)Ljava/util/List;

    .line 776
    .line 777
    .line 778
    move-result-object v4

    .line 779
    const/4 v6, 0x1

    .line 780
    invoke-direct {v14, v4, v6}, Lv9/c0;-><init>(Ljava/util/List;I)V

    .line 781
    .line 782
    .line 783
    invoke-direct {v11, v14, v13}, Lv9/j;-><init>(Lv9/c0;Ljava/lang/String;)V

    .line 784
    .line 785
    .line 786
    invoke-direct {v0, v11}, Lv9/w;-><init>(Lv9/h;)V

    .line 787
    .line 788
    .line 789
    :goto_9
    invoke-virtual {v3, v10, v10}, Landroid/util/SparseIntArray;->put(II)V

    .line 790
    .line 791
    .line 792
    invoke-virtual {v2, v10, v0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 793
    .line 794
    .line 795
    :goto_a
    move-object/from16 v0, p0

    .line 796
    .line 797
    move v13, v15

    .line 798
    move-object/from16 v4, v25

    .line 799
    .line 800
    move-object/from16 v6, v31

    .line 801
    .line 802
    const/4 v10, 0x0

    .line 803
    const/16 v11, 0xc

    .line 804
    .line 805
    const/16 v14, 0xd

    .line 806
    .line 807
    const/4 v15, 0x4

    .line 808
    goto/16 :goto_1

    .line 809
    .line 810
    :cond_21
    move-object/from16 v31, v6

    .line 811
    .line 812
    invoke-virtual {v3}, Landroid/util/SparseIntArray;->size()I

    .line 813
    .line 814
    .line 815
    move-result v0

    .line 816
    const/4 v6, 0x0

    .line 817
    :goto_b
    if-ge v6, v0, :cond_23

    .line 818
    .line 819
    invoke-virtual {v3, v6}, Landroid/util/SparseIntArray;->keyAt(I)I

    .line 820
    .line 821
    .line 822
    move-result v1

    .line 823
    invoke-virtual {v3, v6}, Landroid/util/SparseIntArray;->valueAt(I)I

    .line 824
    .line 825
    .line 826
    move-result v4

    .line 827
    const/4 v9, 0x1

    .line 828
    invoke-virtual {v7, v1, v9}, Landroid/util/SparseBooleanArray;->put(IZ)V

    .line 829
    .line 830
    .line 831
    iget-object v10, v5, Lv9/d0;->i:Landroid/util/SparseBooleanArray;

    .line 832
    .line 833
    invoke-virtual {v10, v4, v9}, Landroid/util/SparseBooleanArray;->put(IZ)V

    .line 834
    .line 835
    .line 836
    invoke-virtual {v2, v6}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 837
    .line 838
    .line 839
    move-result-object v9

    .line 840
    check-cast v9, Lv9/f0;

    .line 841
    .line 842
    if-eqz v9, :cond_22

    .line 843
    .line 844
    iget-object v10, v5, Lv9/d0;->l:Lo8/q;

    .line 845
    .line 846
    new-instance v11, Lh11/h;

    .line 847
    .line 848
    const/16 v13, 0x2000

    .line 849
    .line 850
    invoke-direct {v11, v12, v1, v13}, Lh11/h;-><init>(III)V

    .line 851
    .line 852
    .line 853
    invoke-interface {v9, v8, v10, v11}, Lv9/f0;->a(Lw7/u;Lo8/q;Lh11/h;)V

    .line 854
    .line 855
    .line 856
    move-object/from16 v1, v31

    .line 857
    .line 858
    invoke-virtual {v1, v4, v9}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 859
    .line 860
    .line 861
    goto :goto_c

    .line 862
    :cond_22
    move-object/from16 v1, v31

    .line 863
    .line 864
    :goto_c
    add-int/lit8 v6, v6, 0x1

    .line 865
    .line 866
    move-object/from16 v31, v1

    .line 867
    .line 868
    goto :goto_b

    .line 869
    :cond_23
    move-object/from16 v4, p0

    .line 870
    .line 871
    move-object/from16 v1, v31

    .line 872
    .line 873
    iget v0, v4, Lca/m;->d:I

    .line 874
    .line 875
    invoke-virtual {v1, v0}, Landroid/util/SparseArray;->remove(I)V

    .line 876
    .line 877
    .line 878
    const/4 v14, 0x0

    .line 879
    iput v14, v5, Lv9/d0;->m:I

    .line 880
    .line 881
    iget-object v0, v5, Lv9/d0;->l:Lo8/q;

    .line 882
    .line 883
    invoke-interface {v0}, Lo8/q;->m()V

    .line 884
    .line 885
    .line 886
    const/4 v9, 0x1

    .line 887
    iput-boolean v9, v5, Lv9/d0;->n:Z

    .line 888
    .line 889
    return-void

    .line 890
    nop

    .line 891
    :pswitch_data_0
    .packed-switch 0xf
        :pswitch_5
        :pswitch_4
        :pswitch_3
    .end packed-switch

    .line 892
    .line 893
    .line 894
    .line 895
    .line 896
    .line 897
    .line 898
    .line 899
    .line 900
    .line 901
    :pswitch_data_1
    .packed-switch 0x80
        :pswitch_7
        :pswitch_2
        :pswitch_0
    .end packed-switch

    .line 902
    .line 903
    .line 904
    .line 905
    .line 906
    .line 907
    .line 908
    .line 909
    .line 910
    .line 911
    :pswitch_data_2
    .packed-switch 0x86
        :pswitch_1
        :pswitch_2
        :pswitch_6
    .end packed-switch
.end method

.method public d(I)Lz9/u;
    .locals 3

    .line 1
    iget-object v0, p0, Lca/m;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lz9/v;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x0

    .line 7
    invoke-virtual {p0, p1, v0, v2, v1}, Lca/m;->f(ILz9/u;Lz9/u;Z)Lz9/u;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public e(Ljava/lang/String;Z)Lz9/u;
    .locals 6

    .line 1
    const-string v0, "route"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lca/m;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroidx/collection/b1;

    .line 9
    .line 10
    const-string v1, "<this>"

    .line 11
    .line 12
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    new-instance v1, Landroidx/collection/d1;

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    invoke-direct {v1, v0, v2}, Landroidx/collection/d1;-><init>(Ljava/lang/Object;I)V

    .line 19
    .line 20
    .line 21
    invoke-static {v1}, Lky0/l;->b(Ljava/util/Iterator;)Lky0/j;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    check-cast v0, Lky0/a;

    .line 26
    .line 27
    invoke-virtual {v0}, Lky0/a;->iterator()Ljava/util/Iterator;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    const/4 v2, 0x0

    .line 36
    if-eqz v1, :cond_1

    .line 37
    .line 38
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    move-object v3, v1

    .line 43
    check-cast v3, Lz9/u;

    .line 44
    .line 45
    iget-object v4, v3, Lz9/u;->e:Lca/j;

    .line 46
    .line 47
    iget-object v4, v4, Lca/j;->e:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v4, Ljava/lang/String;

    .line 50
    .line 51
    const/4 v5, 0x0

    .line 52
    invoke-static {v4, p1, v5}, Lly0/w;->p(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 53
    .line 54
    .line 55
    move-result v4

    .line 56
    if-nez v4, :cond_2

    .line 57
    .line 58
    iget-object v3, v3, Lz9/u;->e:Lca/j;

    .line 59
    .line 60
    invoke-virtual {v3, p1}, Lca/j;->h(Ljava/lang/String;)Lz9/t;

    .line 61
    .line 62
    .line 63
    move-result-object v3

    .line 64
    if-eqz v3, :cond_0

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_1
    move-object v1, v2

    .line 68
    :cond_2
    :goto_0
    check-cast v1, Lz9/u;

    .line 69
    .line 70
    if-nez v1, :cond_5

    .line 71
    .line 72
    if-eqz p2, :cond_4

    .line 73
    .line 74
    iget-object p0, p0, Lca/m;->e:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast p0, Lz9/v;

    .line 77
    .line 78
    iget-object p0, p0, Lz9/u;->f:Lz9/v;

    .line 79
    .line 80
    if-eqz p0, :cond_4

    .line 81
    .line 82
    iget-object p0, p0, Lz9/v;->i:Lca/m;

    .line 83
    .line 84
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 85
    .line 86
    .line 87
    invoke-static {p1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 88
    .line 89
    .line 90
    move-result p2

    .line 91
    if-eqz p2, :cond_3

    .line 92
    .line 93
    return-object v2

    .line 94
    :cond_3
    const/4 p2, 0x1

    .line 95
    invoke-virtual {p0, p1, p2}, Lca/m;->e(Ljava/lang/String;Z)Lz9/u;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    return-object p0

    .line 100
    :cond_4
    return-object v2

    .line 101
    :cond_5
    return-object v1
.end method

.method public f(ILz9/u;Lz9/u;Z)Lz9/u;
    .locals 5

    .line 1
    iget-object v0, p0, Lca/m;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lz9/v;

    .line 4
    .line 5
    iget-object p0, p0, Lca/m;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Landroidx/collection/b1;

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Landroidx/collection/b1;->c(I)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v1, Lz9/u;

    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    if-eqz p3, :cond_1

    .line 17
    .line 18
    invoke-static {v1, p3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    if-eqz v3, :cond_0

    .line 23
    .line 24
    iget-object v3, v1, Lz9/u;->f:Lz9/v;

    .line 25
    .line 26
    iget-object v4, p3, Lz9/u;->f:Lz9/v;

    .line 27
    .line 28
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    if-eqz v3, :cond_0

    .line 33
    .line 34
    return-object v1

    .line 35
    :cond_0
    move-object v1, v2

    .line 36
    goto :goto_0

    .line 37
    :cond_1
    if-eqz v1, :cond_2

    .line 38
    .line 39
    return-object v1

    .line 40
    :cond_2
    :goto_0
    if-eqz p4, :cond_6

    .line 41
    .line 42
    new-instance v1, Landroidx/collection/d1;

    .line 43
    .line 44
    const/4 v3, 0x0

    .line 45
    invoke-direct {v1, p0, v3}, Landroidx/collection/d1;-><init>(Ljava/lang/Object;I)V

    .line 46
    .line 47
    .line 48
    invoke-static {v1}, Lky0/l;->b(Ljava/util/Iterator;)Lky0/j;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    check-cast p0, Lky0/a;

    .line 53
    .line 54
    invoke-virtual {p0}, Lky0/a;->iterator()Ljava/util/Iterator;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    :cond_3
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    if-eqz v1, :cond_5

    .line 63
    .line 64
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    check-cast v1, Lz9/u;

    .line 69
    .line 70
    instance-of v3, v1, Lz9/v;

    .line 71
    .line 72
    if-eqz v3, :cond_4

    .line 73
    .line 74
    invoke-virtual {v1, p2}, Lz9/u;->equals(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v3

    .line 78
    if-nez v3, :cond_4

    .line 79
    .line 80
    check-cast v1, Lz9/v;

    .line 81
    .line 82
    const/4 v3, 0x1

    .line 83
    iget-object v1, v1, Lz9/v;->i:Lca/m;

    .line 84
    .line 85
    invoke-virtual {v1, p1, v0, p3, v3}, Lca/m;->f(ILz9/u;Lz9/u;Z)Lz9/u;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    goto :goto_1

    .line 90
    :cond_4
    move-object v1, v2

    .line 91
    :goto_1
    if-eqz v1, :cond_3

    .line 92
    .line 93
    goto :goto_2

    .line 94
    :cond_5
    move-object v1, v2

    .line 95
    :cond_6
    :goto_2
    if-nez v1, :cond_8

    .line 96
    .line 97
    iget-object p0, v0, Lz9/u;->f:Lz9/v;

    .line 98
    .line 99
    if-eqz p0, :cond_7

    .line 100
    .line 101
    invoke-virtual {p0, p2}, Lz9/v;->equals(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result p0

    .line 105
    if-nez p0, :cond_7

    .line 106
    .line 107
    iget-object p0, v0, Lz9/u;->f:Lz9/v;

    .line 108
    .line 109
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    iget-object p0, p0, Lz9/v;->i:Lca/m;

    .line 113
    .line 114
    invoke-virtual {p0, p1, v0, p3, p4}, Lca/m;->f(ILz9/u;Lz9/u;Z)Lz9/u;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    return-object p0

    .line 119
    :cond_7
    return-object v2

    .line 120
    :cond_8
    return-object v1
.end method

.method public g(Ljava/lang/String;)I
    .locals 0

    .line 1
    iget p0, p0, Lca/m;->d:I

    .line 2
    .line 3
    invoke-static {p0, p1}, Landroid/opengl/GLES20;->glGetAttribLocation(ILjava/lang/String;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    invoke-static {p0}, Landroid/opengl/GLES20;->glEnableVertexAttribArray(I)V

    .line 8
    .line 9
    .line 10
    invoke-static {}, Lw7/a;->e()V

    .line 11
    .line 12
    .line 13
    return p0
.end method

.method public h(I)Ln1/t;
    .locals 7

    .line 1
    iget v0, p0, Lca/m;->d:I

    .line 2
    .line 3
    mul-int/2addr p1, v0

    .line 4
    new-instance v1, Ln1/t;

    .line 5
    .line 6
    invoke-virtual {p0}, Lca/m;->j()I

    .line 7
    .line 8
    .line 9
    move-result v2

    .line 10
    sub-int/2addr v2, p1

    .line 11
    if-le v0, v2, :cond_0

    .line 12
    .line 13
    move v0, v2

    .line 14
    :cond_0
    const/4 v2, 0x0

    .line 15
    if-gez v0, :cond_1

    .line 16
    .line 17
    move v0, v2

    .line 18
    :cond_1
    iget-object v3, p0, Lca/m;->h:Ljava/lang/Object;

    .line 19
    .line 20
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    if-ne v0, v3, :cond_2

    .line 25
    .line 26
    iget-object p0, p0, Lca/m;->h:Ljava/lang/Object;

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_2
    new-instance v3, Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-direct {v3, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 32
    .line 33
    .line 34
    :goto_0
    if-ge v2, v0, :cond_3

    .line 35
    .line 36
    const/4 v4, 0x1

    .line 37
    int-to-long v4, v4

    .line 38
    new-instance v6, Ln1/b;

    .line 39
    .line 40
    invoke-direct {v6, v4, v5}, Ln1/b;-><init>(J)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    add-int/lit8 v2, v2, 0x1

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_3
    iput-object v3, p0, Lca/m;->h:Ljava/lang/Object;

    .line 50
    .line 51
    move-object p0, v3

    .line 52
    :goto_1
    invoke-direct {v1, p1, p0}, Ln1/t;-><init>(ILjava/util/List;)V

    .line 53
    .line 54
    .line 55
    return-object v1
.end method

.method public i(I)I
    .locals 1

    .line 1
    invoke-virtual {p0}, Lca/m;->j()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-gtz v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    invoke-virtual {p0}, Lca/m;->j()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-ge p1, v0, :cond_1

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_1
    const-string v0, "ItemIndex > total count"

    .line 17
    .line 18
    invoke-static {v0}, Lj1/b;->a(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    :goto_0
    iget p0, p0, Lca/m;->d:I

    .line 22
    .line 23
    div-int/2addr p1, p0

    .line 24
    return p1
.end method

.method public j()I
    .locals 0

    .line 1
    iget-object p0, p0, Lca/m;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ln1/g;

    .line 4
    .line 5
    iget-object p0, p0, Ln1/g;->d:Lbb/g0;

    .line 6
    .line 7
    iget p0, p0, Lbb/g0;->e:I

    .line 8
    .line 9
    return p0
.end method

.method public k(Lz9/t;Lrn/i;ZLz9/u;)Lz9/t;
    .locals 5

    .line 1
    iget-object p0, p0, Lca/m;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lz9/v;

    .line 4
    .line 5
    new-instance v0, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lz9/v;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    :cond_0
    :goto_0
    move-object v2, v1

    .line 15
    check-cast v2, Lca/l;

    .line 16
    .line 17
    invoke-virtual {v2}, Lca/l;->hasNext()Z

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    const/4 v4, 0x0

    .line 22
    if-eqz v3, :cond_2

    .line 23
    .line 24
    invoke-virtual {v2}, Lca/l;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    check-cast v2, Lz9/u;

    .line 29
    .line 30
    invoke-static {v2, p4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    if-nez v3, :cond_1

    .line 35
    .line 36
    invoke-virtual {v2, p2}, Lz9/u;->m(Lrn/i;)Lz9/t;

    .line 37
    .line 38
    .line 39
    move-result-object v4

    .line 40
    :cond_1
    if-eqz v4, :cond_0

    .line 41
    .line 42
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_2
    invoke-static {v0}, Lmx0/q;->V(Ljava/lang/Iterable;)Ljava/lang/Comparable;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    check-cast v0, Lz9/t;

    .line 51
    .line 52
    iget-object v1, p0, Lz9/u;->f:Lz9/v;

    .line 53
    .line 54
    if-eqz v1, :cond_3

    .line 55
    .line 56
    if-eqz p3, :cond_3

    .line 57
    .line 58
    invoke-virtual {v1, p4}, Lz9/v;->equals(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result p3

    .line 62
    if-nez p3, :cond_3

    .line 63
    .line 64
    invoke-virtual {v1, p2, p0}, Lz9/v;->n(Lrn/i;Lz9/u;)Lz9/t;

    .line 65
    .line 66
    .line 67
    move-result-object v4

    .line 68
    :cond_3
    filled-new-array {p1, v0, v4}, [Lz9/t;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    invoke-static {p0}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    invoke-static {p0}, Lmx0/q;->V(Ljava/lang/Iterable;)Ljava/lang/Comparable;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    check-cast p0, Lz9/t;

    .line 81
    .line 82
    return-object p0
.end method

.method public l(Ljava/lang/String;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lca/m;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lz9/v;

    .line 4
    .line 5
    if-nez p1, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    iget-object v1, v0, Lz9/u;->e:Lca/j;

    .line 10
    .line 11
    iget-object v1, v1, Lca/j;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v1, Ljava/lang/String;

    .line 14
    .line 15
    invoke-virtual {p1, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-nez v1, :cond_2

    .line 20
    .line 21
    invoke-static {p1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-nez v0, :cond_1

    .line 26
    .line 27
    sget v0, Lz9/u;->h:I

    .line 28
    .line 29
    const-string v0, "android-app://androidx.navigation/"

    .line 30
    .line 31
    invoke-virtual {v0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    :goto_0
    iput v0, p0, Lca/m;->d:I

    .line 40
    .line 41
    iput-object p1, p0, Lca/m;->h:Ljava/lang/Object;

    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 45
    .line 46
    const-string p1, "Cannot have an empty start destination route"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    new-instance p0, Ljava/lang/StringBuilder;

    .line 53
    .line 54
    const-string v1, "Start destination "

    .line 55
    .line 56
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    const-string p1, " cannot use the same route as the graph "

    .line 63
    .line 64
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 75
    .line 76
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    throw p1
.end method

.method public m(I)I
    .locals 1

    .line 1
    iget-object p0, p0, Lca/m;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ln1/g;

    .line 4
    .line 5
    iget-object p0, p0, Ln1/g;->d:Lbb/g0;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Lbb/g0;->h(I)Lo1/h;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    iget v0, p0, Lo1/h;->a:I

    .line 12
    .line 13
    sub-int/2addr p1, v0

    .line 14
    iget-object p0, p0, Lo1/h;->c:Lo1/q;

    .line 15
    .line 16
    check-cast p0, Ln1/f;

    .line 17
    .line 18
    iget-object p0, p0, Ln1/f;->a:Lay0/n;

    .line 19
    .line 20
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    sget-object v0, Ln1/s;->a:Ln1/s;

    .line 25
    .line 26
    invoke-interface {p0, v0, p1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    check-cast p0, Ln1/b;

    .line 31
    .line 32
    iget-wide p0, p0, Ln1/b;->a:J

    .line 33
    .line 34
    long-to-int p0, p0

    .line 35
    return p0
.end method
