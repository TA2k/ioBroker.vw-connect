.class public abstract Leb/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/c;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    iput p1, p0, Leb/j0;->d:I

    packed-switch p1, :pswitch_data_0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Ljava/util/concurrent/atomic/AtomicInteger;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    iput-object p1, p0, Leb/j0;->f:Ljava/lang/Object;

    new-instance p1, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    invoke-direct {p1, v0}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    iput-object p1, p0, Leb/j0;->g:Ljava/lang/Object;

    new-instance p1, La8/b;

    const/4 v0, 0x4

    .line 3
    invoke-direct {p1, v0}, La8/b;-><init>(I)V

    iput-object p1, p0, Leb/j0;->e:Ljava/lang/Object;

    return-void

    .line 4
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    iput-object p1, p0, Leb/j0;->e:Ljava/lang/Object;

    .line 6
    iput-object p1, p0, Leb/j0;->f:Ljava/lang/Object;

    .line 7
    sget-object p1, Ls71/o;->g:Ls71/o;

    iput-object p1, p0, Leb/j0;->g:Ljava/lang/Object;

    return-void

    :pswitch_data_0
    .packed-switch 0x6
        :pswitch_0
    .end packed-switch
.end method

.method public constructor <init>(La8/b;)V
    .locals 2

    const/4 v0, 0x2

    iput v0, p0, Leb/j0;->d:I

    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/concurrent/atomic/AtomicInteger;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    iput-object v0, p0, Leb/j0;->f:Ljava/lang/Object;

    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 12
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    iput-object v0, p0, Leb/j0;->g:Ljava/lang/Object;

    iput-object p1, p0, Leb/j0;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Class;)V
    .locals 37

    move-object/from16 v0, p0

    const/4 v1, 0x0

    iput v1, v0, Leb/j0;->d:I

    .line 17
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 18
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    move-result-object v1

    const-string v2, "randomUUID(...)"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object v1, v0, Leb/j0;->e:Ljava/lang/Object;

    .line 19
    new-instance v3, Lmb/o;

    iget-object v1, v0, Leb/j0;->e:Ljava/lang/Object;

    check-cast v1, Ljava/util/UUID;

    invoke-virtual {v1}, Ljava/util/UUID;->toString()Ljava/lang/String;

    move-result-object v4

    const-string v1, "toString(...)"

    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual/range {p1 .. p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v6

    const/16 v35, 0x0

    const v36, 0x1fffffa

    const/4 v5, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const-wide/16 v10, 0x0

    const-wide/16 v12, 0x0

    const-wide/16 v14, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const-wide/16 v19, 0x0

    const-wide/16 v21, 0x0

    const-wide/16 v23, 0x0

    const-wide/16 v25, 0x0

    const/16 v27, 0x0

    const/16 v28, 0x0

    const/16 v29, 0x0

    const-wide/16 v30, 0x0

    const/16 v32, 0x0

    const/16 v33, 0x0

    const/16 v34, 0x0

    .line 20
    invoke-direct/range {v3 .. v36}, Lmb/o;-><init>(Ljava/lang/String;Leb/h0;Ljava/lang/String;Ljava/lang/String;Leb/h;Leb/h;JJJLeb/e;ILeb/a;JJJJZLeb/e0;IJIILjava/lang/String;Ljava/lang/Boolean;I)V

    .line 21
    iput-object v3, v0, Leb/j0;->f:Ljava/lang/Object;

    .line 22
    invoke-virtual/range {p1 .. p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Ljp/m1;->g([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v1

    iput-object v1, v0, Leb/j0;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Class;[Lor/a;)V
    .locals 6

    const/4 v0, 0x4

    iput v0, p0, Leb/j0;->d:I

    .line 23
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 24
    iput-object p1, p0, Leb/j0;->e:Ljava/lang/Object;

    .line 25
    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    .line 26
    array-length v0, p2

    const/4 v1, 0x0

    move v2, v1

    :goto_0
    const-class v3, Lmr/b;

    if-ge v2, v0, :cond_1

    aget-object v4, p2, v2

    .line 27
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 28
    invoke-virtual {p1, v3}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_0

    .line 29
    invoke-virtual {p1, v3, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 30
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    new-instance p1, Ljava/lang/StringBuilder;

    const-string p2, "KeyTypeManager constructed with duplicate factories for primitive "

    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 31
    invoke-virtual {v3}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 32
    :cond_1
    array-length v0, p2

    if-lez v0, :cond_2

    .line 33
    aget-object p2, p2, v1

    .line 34
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 35
    iput-object v3, p0, Leb/j0;->g:Ljava/lang/Object;

    goto :goto_1

    .line 36
    :cond_2
    const-class p2, Ljava/lang/Void;

    iput-object p2, p0, Leb/j0;->g:Ljava/lang/Object;

    .line 37
    :goto_1
    invoke-static {p1}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    move-result-object p1

    iput-object p1, p0, Leb/j0;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Object;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Leb/j0;->d:I

    .line 38
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Leb/j0;->e:Ljava/lang/Object;

    .line 39
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 40
    iput-object v0, p0, Leb/j0;->f:Ljava/lang/Object;

    .line 41
    iput-object p1, p0, Leb/j0;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Leb/j0;->d:I

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    invoke-static {p1}, Lno/c0;->e(Ljava/lang/String;)V

    new-instance v0, Landroid/os/Bundle;

    .line 10
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    iput-object v0, p0, Leb/j0;->e:Ljava/lang/Object;

    iput-object p1, p0, Leb/j0;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ls41/c;[Llx0/l;)V
    .locals 1

    const/4 v0, 0x5

    iput v0, p0, Leb/j0;->d:I

    const-string v0, "contextData"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    iput-object p1, p0, Leb/j0;->e:Ljava/lang/Object;

    .line 15
    iput-object p2, p0, Leb/j0;->f:Ljava/lang/Object;

    .line 16
    invoke-static {p3}, Lmx0/n;->b([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    iput-object p1, p0, Leb/j0;->g:Ljava/lang/Object;

    return-void
.end method

.method public static y(Ljava/util/ArrayList;III)V
    .locals 2

    .line 1
    if-le p1, p2, :cond_0

    .line 2
    .line 3
    move v0, p2

    .line 4
    goto :goto_0

    .line 5
    :cond_0
    sub-int v0, p2, p3

    .line 6
    .line 7
    :goto_0
    const/4 v1, 0x1

    .line 8
    if-ne p3, v1, :cond_3

    .line 9
    .line 10
    add-int/lit8 p3, p2, 0x1

    .line 11
    .line 12
    if-eq p1, p3, :cond_2

    .line 13
    .line 14
    add-int/lit8 p3, p2, -0x1

    .line 15
    .line 16
    if-ne p1, p3, :cond_1

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_1
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    invoke-virtual {p0, v0, p1}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :cond_2
    :goto_1
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p3

    .line 31
    invoke-virtual {p0, p2, p3}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p2

    .line 35
    invoke-virtual {p0, p1, p2}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :cond_3
    add-int/2addr p3, p1

    .line 40
    invoke-virtual {p0, p1, p3}, Ljava/util/ArrayList;->subList(II)Ljava/util/List;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    move-object p2, p1

    .line 45
    check-cast p2, Ljava/util/Collection;

    .line 46
    .line 47
    invoke-static {p2}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 48
    .line 49
    .line 50
    move-result-object p2

    .line 51
    invoke-interface {p1}, Ljava/util/List;->clear()V

    .line 52
    .line 53
    .line 54
    invoke-virtual {p0, v0, p2}, Ljava/util/ArrayList;->addAll(ILjava/util/Collection;)Z

    .line 55
    .line 56
    .line 57
    return-void
.end method


# virtual methods
.method public abstract A(Lcom/google/crypto/tink/shaded/protobuf/i;)Lcom/google/crypto/tink/shaded/protobuf/a;
.end method

.method public varargs B(Ljava/lang/String;[Leb/j0;)V
    .locals 7

    .line 1
    invoke-static {p2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    array-length v0, p2

    .line 5
    if-lez v0, :cond_7

    .line 6
    .line 7
    new-array v1, v0, [Lcom/google/firebase/appindexing/internal/Thing;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    move v3, v2

    .line 11
    :goto_0
    array-length v4, p2

    .line 12
    const-string v5, " is null and is ignored by put method."

    .line 13
    .line 14
    if-ge v3, v4, :cond_1

    .line 15
    .line 16
    aget-object v4, p2, v3

    .line 17
    .line 18
    if-nez v4, :cond_0

    .line 19
    .line 20
    new-instance v4, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    const-string v6, "Builder at "

    .line 23
    .line 24
    invoke-direct {v4, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v4

    .line 37
    invoke-static {v4}, Lbp/m;->c(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_0
    invoke-virtual {v4}, Leb/j0;->a()Lcom/google/firebase/appindexing/internal/Thing;

    .line 42
    .line 43
    .line 44
    move-result-object v4

    .line 45
    aput-object v4, v1, v3

    .line 46
    .line 47
    :goto_1
    add-int/lit8 v3, v3, 0x1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_1
    iget-object p0, p0, Leb/j0;->e:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast p0, Landroid/os/Bundle;

    .line 53
    .line 54
    if-lez v0, :cond_6

    .line 55
    .line 56
    move p2, v2

    .line 57
    :goto_2
    if-ge v2, v0, :cond_3

    .line 58
    .line 59
    aget-object v3, v1, v2

    .line 60
    .line 61
    aput-object v3, v1, p2

    .line 62
    .line 63
    aget-object v3, v1, v2

    .line 64
    .line 65
    if-nez v3, :cond_2

    .line 66
    .line 67
    new-instance v3, Ljava/lang/StringBuilder;

    .line 68
    .line 69
    const-string v4, "Thing at "

    .line 70
    .line 71
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v3

    .line 84
    invoke-static {v3}, Lbp/m;->c(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    goto :goto_3

    .line 88
    :cond_2
    add-int/lit8 p2, p2, 0x1

    .line 89
    .line 90
    :goto_3
    add-int/lit8 v2, v2, 0x1

    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_3
    if-lez p2, :cond_5

    .line 94
    .line 95
    invoke-static {v1, p2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p2

    .line 99
    check-cast p2, [Lcom/google/firebase/appindexing/internal/Thing;

    .line 100
    .line 101
    array-length v0, p2

    .line 102
    const/16 v1, 0x64

    .line 103
    .line 104
    if-ge v0, v1, :cond_4

    .line 105
    .line 106
    goto :goto_4

    .line 107
    :cond_4
    const-string v0, "Input Array of elements is too big, cutting off."

    .line 108
    .line 109
    invoke-static {v0}, Lbp/m;->c(Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    invoke-static {p2, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object p2

    .line 116
    :goto_4
    check-cast p2, [Landroid/os/Parcelable;

    .line 117
    .line 118
    invoke-virtual {p0, p1, p2}, Landroid/os/Bundle;->putParcelableArray(Ljava/lang/String;[Landroid/os/Parcelable;)V

    .line 119
    .line 120
    .line 121
    :cond_5
    return-void

    .line 122
    :cond_6
    const-string p0, "Thing array is empty and is ignored by put method."

    .line 123
    .line 124
    invoke-static {p0}, Lbp/m;->c(Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    return-void

    .line 128
    :cond_7
    const-string p0, "Builder array is empty and is ignored by put method."

    .line 129
    .line 130
    invoke-static {p0}, Lbp/m;->c(Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    return-void
.end method

.method public varargs C(Ljava/lang/String;[Ljava/lang/String;)V
    .locals 7

    .line 1
    iget-object p0, p0, Leb/j0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/os/Bundle;

    .line 4
    .line 5
    array-length v0, p2

    .line 6
    invoke-static {p2, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p2

    .line 10
    check-cast p2, [Ljava/lang/String;

    .line 11
    .line 12
    array-length v0, p2

    .line 13
    if-lez v0, :cond_7

    .line 14
    .line 15
    const/4 v0, 0x0

    .line 16
    move v1, v0

    .line 17
    move v2, v1

    .line 18
    :goto_0
    array-length v3, p2

    .line 19
    const/16 v4, 0x64

    .line 20
    .line 21
    invoke-static {v3, v4}, Ljava/lang/Math;->min(II)I

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    if-ge v1, v3, :cond_4

    .line 26
    .line 27
    aget-object v3, p2, v1

    .line 28
    .line 29
    aput-object v3, p2, v2

    .line 30
    .line 31
    aget-object v4, p2, v1

    .line 32
    .line 33
    const-string v5, "String at "

    .line 34
    .line 35
    if-nez v4, :cond_0

    .line 36
    .line 37
    new-instance v3, Ljava/lang/StringBuilder;

    .line 38
    .line 39
    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string v4, " is null and is ignored by put method."

    .line 46
    .line 47
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v3

    .line 54
    invoke-static {v3}, Lbp/m;->c(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_0
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 59
    .line 60
    .line 61
    move-result v3

    .line 62
    const/16 v4, 0x4e20

    .line 63
    .line 64
    if-le v3, v4, :cond_3

    .line 65
    .line 66
    new-instance v3, Ljava/lang/StringBuilder;

    .line 67
    .line 68
    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    const-string v5, " is too long, truncating string."

    .line 75
    .line 76
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    invoke-static {v3}, Lbp/m;->c(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    aget-object v3, p2, v2

    .line 87
    .line 88
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 89
    .line 90
    .line 91
    move-result v5

    .line 92
    if-gt v5, v4, :cond_1

    .line 93
    .line 94
    goto :goto_1

    .line 95
    :cond_1
    const/16 v5, 0x4e1f

    .line 96
    .line 97
    invoke-virtual {v3, v5}, Ljava/lang/String;->charAt(I)C

    .line 98
    .line 99
    .line 100
    move-result v6

    .line 101
    invoke-static {v6}, Ljava/lang/Character;->isHighSurrogate(C)Z

    .line 102
    .line 103
    .line 104
    move-result v6

    .line 105
    if-eqz v6, :cond_2

    .line 106
    .line 107
    invoke-virtual {v3, v4}, Ljava/lang/String;->charAt(I)C

    .line 108
    .line 109
    .line 110
    move-result v6

    .line 111
    invoke-static {v6}, Ljava/lang/Character;->isLowSurrogate(C)Z

    .line 112
    .line 113
    .line 114
    move-result v6

    .line 115
    if-eqz v6, :cond_2

    .line 116
    .line 117
    move v4, v5

    .line 118
    :cond_2
    invoke-virtual {v3, v0, v4}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v3

    .line 122
    :goto_1
    aput-object v3, p2, v2

    .line 123
    .line 124
    :cond_3
    add-int/lit8 v2, v2, 0x1

    .line 125
    .line 126
    :goto_2
    add-int/lit8 v1, v1, 0x1

    .line 127
    .line 128
    goto :goto_0

    .line 129
    :cond_4
    if-lez v2, :cond_6

    .line 130
    .line 131
    invoke-static {p2, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p2

    .line 135
    check-cast p2, [Ljava/lang/String;

    .line 136
    .line 137
    array-length v0, p2

    .line 138
    if-ge v0, v4, :cond_5

    .line 139
    .line 140
    goto :goto_3

    .line 141
    :cond_5
    const-string v0, "Input Array of elements is too big, cutting off."

    .line 142
    .line 143
    invoke-static {v0}, Lbp/m;->c(Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    invoke-static {p2, v4}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object p2

    .line 150
    :goto_3
    check-cast p2, [Ljava/lang/String;

    .line 151
    .line 152
    invoke-virtual {p0, p1, p2}, Landroid/os/BaseBundle;->putStringArray(Ljava/lang/String;[Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    :cond_6
    return-void

    .line 156
    :cond_7
    const-string p0, "String array is empty and is ignored by put method."

    .line 157
    .line 158
    invoke-static {p0}, Lbp/m;->c(Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    return-void
.end method

.method public abstract D()V
.end method

.method public abstract E(Lmv/a;)Ljava/lang/Object;
.end method

.method public abstract F(I)Z
.end method

.method public abstract G(Ls71/o;Lv71/f;Lv71/f;)Ls71/o;
.end method

.method public abstract H(Ls71/o;)Z
.end method

.method public abstract I(Lcom/google/crypto/tink/shaded/protobuf/a;)V
.end method

.method public a()Lcom/google/firebase/appindexing/internal/Thing;
    .locals 9

    .line 1
    new-instance v0, Lcom/google/firebase/appindexing/internal/Thing;

    .line 2
    .line 3
    new-instance v1, Landroid/os/Bundle;

    .line 4
    .line 5
    iget-object v2, p0, Leb/j0;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Landroid/os/Bundle;

    .line 8
    .line 9
    invoke-direct {v1, v2}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    .line 10
    .line 11
    .line 12
    new-instance v7, Landroid/os/Bundle;

    .line 13
    .line 14
    invoke-direct {v7}, Landroid/os/Bundle;-><init>()V

    .line 15
    .line 16
    .line 17
    new-instance v3, Lfs/h;

    .line 18
    .line 19
    new-instance v8, Landroid/os/Bundle;

    .line 20
    .line 21
    invoke-direct {v8}, Landroid/os/Bundle;-><init>()V

    .line 22
    .line 23
    .line 24
    const-string v6, ""

    .line 25
    .line 26
    const/4 v4, 0x0

    .line 27
    const/4 v5, 0x0

    .line 28
    invoke-direct/range {v3 .. v8}, Lfs/h;-><init>(ZILjava/lang/String;Landroid/os/Bundle;Landroid/os/Bundle;)V

    .line 29
    .line 30
    .line 31
    iget-object v2, p0, Leb/j0;->g:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v2, Ljava/lang/String;

    .line 34
    .line 35
    iget-object p0, p0, Leb/j0;->f:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p0, Ljava/lang/String;

    .line 38
    .line 39
    invoke-direct {v0, v1, v3, v2, p0}, Lcom/google/firebase/appindexing/internal/Thing;-><init>(Landroid/os/Bundle;Lfs/h;Ljava/lang/String;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    return-object v0
.end method

.method public g()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Leb/j0;->g:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public h()Leb/k0;
    .locals 43

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-virtual {v0}, Leb/j0;->i()Leb/k0;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    iget-object v2, v0, Leb/j0;->f:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v2, Lmb/o;

    .line 10
    .line 11
    iget-object v2, v2, Lmb/o;->j:Leb/e;

    .line 12
    .line 13
    invoke-virtual {v2}, Leb/e;->b()Z

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    const/4 v4, 0x1

    .line 18
    const/4 v5, 0x0

    .line 19
    if-nez v3, :cond_1

    .line 20
    .line 21
    iget-boolean v3, v2, Leb/e;->e:Z

    .line 22
    .line 23
    if-nez v3, :cond_1

    .line 24
    .line 25
    iget-boolean v3, v2, Leb/e;->c:Z

    .line 26
    .line 27
    if-nez v3, :cond_1

    .line 28
    .line 29
    iget-boolean v2, v2, Leb/e;->d:Z

    .line 30
    .line 31
    if-eqz v2, :cond_0

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    move v2, v5

    .line 35
    goto :goto_1

    .line 36
    :cond_1
    :goto_0
    move v2, v4

    .line 37
    :goto_1
    iget-object v3, v0, Leb/j0;->f:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v3, Lmb/o;

    .line 40
    .line 41
    iget-boolean v6, v3, Lmb/o;->q:Z

    .line 42
    .line 43
    if-eqz v6, :cond_4

    .line 44
    .line 45
    if-nez v2, :cond_3

    .line 46
    .line 47
    iget-wide v6, v3, Lmb/o;->g:J

    .line 48
    .line 49
    const-wide/16 v8, 0x0

    .line 50
    .line 51
    cmp-long v2, v6, v8

    .line 52
    .line 53
    if-gtz v2, :cond_2

    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_2
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 57
    .line 58
    const-string v1, "Expedited jobs cannot be delayed"

    .line 59
    .line 60
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    throw v0

    .line 64
    :cond_3
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 65
    .line 66
    const-string v1, "Expedited jobs only support network and storage constraints"

    .line 67
    .line 68
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    throw v0

    .line 72
    :cond_4
    :goto_2
    iget-object v2, v3, Lmb/o;->x:Ljava/lang/String;

    .line 73
    .line 74
    const/16 v6, 0x7f

    .line 75
    .line 76
    if-nez v2, :cond_7

    .line 77
    .line 78
    iget-object v2, v3, Lmb/o;->c:Ljava/lang/String;

    .line 79
    .line 80
    const-string v7, "."

    .line 81
    .line 82
    filled-new-array {v7}, [Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v7

    .line 86
    const/4 v8, 0x6

    .line 87
    invoke-static {v2, v7, v8}, Lly0/p;->Y(Ljava/lang/CharSequence;[Ljava/lang/String;I)Ljava/util/List;

    .line 88
    .line 89
    .line 90
    move-result-object v2

    .line 91
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 92
    .line 93
    .line 94
    move-result v7

    .line 95
    if-ne v7, v4, :cond_5

    .line 96
    .line 97
    invoke-interface {v2, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v2

    .line 101
    check-cast v2, Ljava/lang/String;

    .line 102
    .line 103
    goto :goto_3

    .line 104
    :cond_5
    invoke-static {v2}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v2

    .line 108
    check-cast v2, Ljava/lang/String;

    .line 109
    .line 110
    :goto_3
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 111
    .line 112
    .line 113
    move-result v4

    .line 114
    if-gt v4, v6, :cond_6

    .line 115
    .line 116
    goto :goto_4

    .line 117
    :cond_6
    invoke-static {v6, v2}, Lly0/p;->j0(ILjava/lang/String;)Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v2

    .line 121
    :goto_4
    iput-object v2, v3, Lmb/o;->x:Ljava/lang/String;

    .line 122
    .line 123
    goto :goto_5

    .line 124
    :cond_7
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 125
    .line 126
    .line 127
    move-result v3

    .line 128
    if-le v3, v6, :cond_8

    .line 129
    .line 130
    iget-object v3, v0, Leb/j0;->f:Ljava/lang/Object;

    .line 131
    .line 132
    check-cast v3, Lmb/o;

    .line 133
    .line 134
    invoke-static {v6, v2}, Lly0/p;->j0(ILjava/lang/String;)Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    iput-object v2, v3, Lmb/o;->x:Ljava/lang/String;

    .line 139
    .line 140
    :cond_8
    :goto_5
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 141
    .line 142
    .line 143
    move-result-object v2

    .line 144
    const-string v3, "randomUUID(...)"

    .line 145
    .line 146
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    iput-object v2, v0, Leb/j0;->e:Ljava/lang/Object;

    .line 150
    .line 151
    new-instance v4, Lmb/o;

    .line 152
    .line 153
    invoke-virtual {v2}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object v5

    .line 157
    const-string v2, "toString(...)"

    .line 158
    .line 159
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    iget-object v2, v0, Leb/j0;->f:Ljava/lang/Object;

    .line 163
    .line 164
    check-cast v2, Lmb/o;

    .line 165
    .line 166
    const-string v3, "other"

    .line 167
    .line 168
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    iget-object v7, v2, Lmb/o;->c:Ljava/lang/String;

    .line 172
    .line 173
    iget-object v6, v2, Lmb/o;->b:Leb/h0;

    .line 174
    .line 175
    iget-object v8, v2, Lmb/o;->d:Ljava/lang/String;

    .line 176
    .line 177
    new-instance v9, Leb/h;

    .line 178
    .line 179
    iget-object v3, v2, Lmb/o;->e:Leb/h;

    .line 180
    .line 181
    invoke-direct {v9, v3}, Leb/h;-><init>(Leb/h;)V

    .line 182
    .line 183
    .line 184
    new-instance v10, Leb/h;

    .line 185
    .line 186
    iget-object v3, v2, Lmb/o;->f:Leb/h;

    .line 187
    .line 188
    invoke-direct {v10, v3}, Leb/h;-><init>(Leb/h;)V

    .line 189
    .line 190
    .line 191
    iget-wide v11, v2, Lmb/o;->g:J

    .line 192
    .line 193
    iget-wide v13, v2, Lmb/o;->h:J

    .line 194
    .line 195
    move-object v15, v4

    .line 196
    iget-wide v3, v2, Lmb/o;->i:J

    .line 197
    .line 198
    move-object/from16 v38, v1

    .line 199
    .line 200
    new-instance v1, Leb/e;

    .line 201
    .line 202
    move-wide/from16 v16, v3

    .line 203
    .line 204
    iget-object v3, v2, Lmb/o;->j:Leb/e;

    .line 205
    .line 206
    invoke-direct {v1, v3}, Leb/e;-><init>(Leb/e;)V

    .line 207
    .line 208
    .line 209
    iget v3, v2, Lmb/o;->k:I

    .line 210
    .line 211
    iget-object v4, v2, Lmb/o;->l:Leb/a;

    .line 212
    .line 213
    move/from16 v18, v3

    .line 214
    .line 215
    move-object/from16 v19, v4

    .line 216
    .line 217
    iget-wide v3, v2, Lmb/o;->m:J

    .line 218
    .line 219
    move-wide/from16 v20, v3

    .line 220
    .line 221
    iget-wide v3, v2, Lmb/o;->n:J

    .line 222
    .line 223
    move-wide/from16 v22, v3

    .line 224
    .line 225
    iget-wide v3, v2, Lmb/o;->o:J

    .line 226
    .line 227
    move-wide/from16 v24, v3

    .line 228
    .line 229
    iget-wide v3, v2, Lmb/o;->p:J

    .line 230
    .line 231
    move-object/from16 v26, v1

    .line 232
    .line 233
    iget-boolean v1, v2, Lmb/o;->q:Z

    .line 234
    .line 235
    move/from16 v28, v1

    .line 236
    .line 237
    iget-object v1, v2, Lmb/o;->r:Leb/e0;

    .line 238
    .line 239
    move-object/from16 v29, v1

    .line 240
    .line 241
    iget v1, v2, Lmb/o;->s:I

    .line 242
    .line 243
    move-wide/from16 v30, v3

    .line 244
    .line 245
    iget-wide v3, v2, Lmb/o;->u:J

    .line 246
    .line 247
    move/from16 v27, v1

    .line 248
    .line 249
    iget v1, v2, Lmb/o;->v:I

    .line 250
    .line 251
    move/from16 v33, v1

    .line 252
    .line 253
    iget v1, v2, Lmb/o;->w:I

    .line 254
    .line 255
    move/from16 v34, v1

    .line 256
    .line 257
    iget-object v1, v2, Lmb/o;->x:Ljava/lang/String;

    .line 258
    .line 259
    iget-object v2, v2, Lmb/o;->y:Ljava/lang/Boolean;

    .line 260
    .line 261
    const/high16 v37, 0x80000

    .line 262
    .line 263
    move-object/from16 v35, v1

    .line 264
    .line 265
    move-object/from16 v36, v2

    .line 266
    .line 267
    move-wide/from16 v39, v3

    .line 268
    .line 269
    move-object v4, v15

    .line 270
    move-wide/from16 v15, v16

    .line 271
    .line 272
    move-object/from16 v17, v26

    .line 273
    .line 274
    move-wide/from16 v41, v30

    .line 275
    .line 276
    move/from16 v30, v27

    .line 277
    .line 278
    move-wide/from16 v31, v39

    .line 279
    .line 280
    move-wide/from16 v26, v41

    .line 281
    .line 282
    invoke-direct/range {v4 .. v37}, Lmb/o;-><init>(Ljava/lang/String;Leb/h0;Ljava/lang/String;Ljava/lang/String;Leb/h;Leb/h;JJJLeb/e;ILeb/a;JJJJZLeb/e0;IJIILjava/lang/String;Ljava/lang/Boolean;I)V

    .line 283
    .line 284
    .line 285
    move-object v15, v4

    .line 286
    iput-object v15, v0, Leb/j0;->f:Ljava/lang/Object;

    .line 287
    .line 288
    return-object v38
.end method

.method public abstract i()Leb/k0;
.end method

.method public abstract j(Lv71/h;I)Ljava/util/ArrayList;
.end method

.method public l(Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget-object v0, p0, Leb/j0;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    iget-object v1, p0, Leb/j0;->g:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Leb/j0;->g:Ljava/lang/Object;

    .line 11
    .line 12
    return-void
.end method

.method public n(Lv71/h;)Lv71/b;
    .locals 34

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-interface {v1}, Lv71/h;->d()Lw71/b;

    .line 6
    .line 7
    .line 8
    move-result-object v6

    .line 9
    new-instance v5, Lv71/f;

    .line 10
    .line 11
    iget-object v2, v6, Lw71/b;->a:Lw71/c;

    .line 12
    .line 13
    iget-wide v3, v6, Lw71/b;->b:D

    .line 14
    .line 15
    invoke-virtual {v0}, Leb/j0;->v()Ll71/z;

    .line 16
    .line 17
    .line 18
    move-result-object v7

    .line 19
    iget-object v7, v7, Ll71/z;->b:Lv71/e;

    .line 20
    .line 21
    invoke-direct {v5, v2, v3, v4, v7}, Lv71/f;-><init>(Lw71/c;DLv71/e;)V

    .line 22
    .line 23
    .line 24
    invoke-interface {v1}, Lv71/h;->d()Lw71/b;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    invoke-interface {v1}, Lv71/h;->e()Ljava/util/List;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    invoke-interface {v1}, Lv71/h;->f()I

    .line 33
    .line 34
    .line 35
    move-result v4

    .line 36
    invoke-interface {v1}, Lv71/h;->b()Ls71/o;

    .line 37
    .line 38
    .line 39
    move-result-object v7

    .line 40
    new-instance v8, Lv71/d;

    .line 41
    .line 42
    iget-object v9, v5, Lv71/f;->e:Lv71/g;

    .line 43
    .line 44
    iget-object v10, v9, Lv71/g;->a:Lw71/c;

    .line 45
    .line 46
    iget-object v11, v5, Lv71/f;->d:Lv71/g;

    .line 47
    .line 48
    iget-object v12, v11, Lv71/g;->a:Lw71/c;

    .line 49
    .line 50
    filled-new-array {v10, v12}, [Lw71/c;

    .line 51
    .line 52
    .line 53
    move-result-object v10

    .line 54
    invoke-static {v10}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 55
    .line 56
    .line 57
    move-result-object v10

    .line 58
    iget-object v9, v9, Lv71/g;->b:Lw71/c;

    .line 59
    .line 60
    iget-object v11, v11, Lv71/g;->b:Lw71/c;

    .line 61
    .line 62
    filled-new-array {v9, v11}, [Lw71/c;

    .line 63
    .line 64
    .line 65
    move-result-object v9

    .line 66
    invoke-static {v9}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 67
    .line 68
    .line 69
    move-result-object v9

    .line 70
    invoke-direct {v8, v10, v9}, Lv71/d;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 71
    .line 72
    .line 73
    const-string v9, "vehiclePosition"

    .line 74
    .line 75
    invoke-static {v2, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    const-string v10, "trajectoryPoints"

    .line 79
    .line 80
    invoke-static {v3, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    iget-wide v10, v2, Lw71/b;->b:D

    .line 84
    .line 85
    const-wide v12, 0x3ff921fb54442d18L    # 1.5707963267948966

    .line 86
    .line 87
    .line 88
    .line 89
    .line 90
    add-double/2addr v10, v12

    .line 91
    const-wide v12, 0x4062c00000000000L    # 150.0

    .line 92
    .line 93
    .line 94
    .line 95
    .line 96
    invoke-static {v10, v11, v12, v13}, Lw71/d;->c(DD)Lw71/c;

    .line 97
    .line 98
    .line 99
    move-result-object v10

    .line 100
    iget-object v2, v2, Lw71/b;->a:Lw71/c;

    .line 101
    .line 102
    invoke-static {v2, v10}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 103
    .line 104
    .line 105
    move-result-object v10

    .line 106
    invoke-static {v10, v2}, Lw71/d;->f(Lw71/c;Lw71/c;)Lw71/c;

    .line 107
    .line 108
    .line 109
    move-result-object v10

    .line 110
    invoke-static {v2, v10}, Lmb/e;->o(Lw71/c;Lw71/c;)Lw71/a;

    .line 111
    .line 112
    .line 113
    move-result-object v2

    .line 114
    const/16 v16, -0x2

    .line 115
    .line 116
    if-nez v2, :cond_0

    .line 117
    .line 118
    move/from16 v10, v16

    .line 119
    .line 120
    const-wide v17, 0x3fa999999999999aL    # 0.05

    .line 121
    .line 122
    .line 123
    .line 124
    .line 125
    goto/16 :goto_8

    .line 126
    .line 127
    :cond_0
    add-int/lit8 v13, v4, -0x1

    .line 128
    .line 129
    const/4 v10, 0x0

    .line 130
    const-wide v17, 0x3fa999999999999aL    # 0.05

    .line 131
    .line 132
    .line 133
    .line 134
    .line 135
    :goto_0
    if-ge v10, v13, :cond_a

    .line 136
    .line 137
    invoke-static {v10, v3}, Llp/bd;->d(ILjava/util/List;)Llx0/l;

    .line 138
    .line 139
    .line 140
    move-result-object v11

    .line 141
    if-nez v11, :cond_2

    .line 142
    .line 143
    :cond_1
    move-object/from16 v24, v2

    .line 144
    .line 145
    move-object/from16 v23, v3

    .line 146
    .line 147
    move/from16 v22, v13

    .line 148
    .line 149
    goto/16 :goto_7

    .line 150
    .line 151
    :cond_2
    iget-object v15, v11, Llx0/l;->d:Ljava/lang/Object;

    .line 152
    .line 153
    check-cast v15, Lw71/c;

    .line 154
    .line 155
    iget-object v11, v11, Llx0/l;->e:Ljava/lang/Object;

    .line 156
    .line 157
    check-cast v11, Lw71/c;

    .line 158
    .line 159
    const-string v14, "point1"

    .line 160
    .line 161
    invoke-static {v15, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    const-string v14, "point2"

    .line 165
    .line 166
    invoke-static {v11, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    invoke-static {v11, v15}, Lw71/d;->f(Lw71/c;Lw71/c;)Lw71/c;

    .line 170
    .line 171
    .line 172
    move-result-object v14

    .line 173
    invoke-static {v15, v14}, Lmb/e;->o(Lw71/c;Lw71/c;)Lw71/a;

    .line 174
    .line 175
    .line 176
    move-result-object v14

    .line 177
    if-eqz v14, :cond_3

    .line 178
    .line 179
    invoke-virtual {v14, v2}, Lw71/a;->b(Lw71/a;)Lw71/c;

    .line 180
    .line 181
    .line 182
    move-result-object v14

    .line 183
    goto :goto_1

    .line 184
    :cond_3
    const/4 v14, 0x0

    .line 185
    :goto_1
    if-eqz v14, :cond_1

    .line 186
    .line 187
    move/from16 v22, v13

    .line 188
    .line 189
    invoke-static {v15, v11}, Lw71/d;->a(Lw71/c;Lw71/c;)D

    .line 190
    .line 191
    .line 192
    move-result-wide v12

    .line 193
    move-object/from16 v24, v2

    .line 194
    .line 195
    move-object/from16 v23, v3

    .line 196
    .line 197
    invoke-static {v15, v14}, Lw71/d;->a(Lw71/c;Lw71/c;)D

    .line 198
    .line 199
    .line 200
    move-result-wide v2

    .line 201
    invoke-static {v11, v14}, Lw71/d;->a(Lw71/c;Lw71/c;)D

    .line 202
    .line 203
    .line 204
    move-result-wide v14

    .line 205
    const/4 v11, 0x5

    .line 206
    invoke-static {v11, v2, v3}, Llp/yc;->a(ID)D

    .line 207
    .line 208
    .line 209
    move-result-wide v25

    .line 210
    invoke-static {v11, v12, v13}, Llp/yc;->a(ID)D

    .line 211
    .line 212
    .line 213
    move-result-wide v27

    .line 214
    cmpg-double v21, v25, v27

    .line 215
    .line 216
    if-gtz v21, :cond_4

    .line 217
    .line 218
    invoke-static {v11, v14, v15}, Llp/yc;->a(ID)D

    .line 219
    .line 220
    .line 221
    move-result-wide v25

    .line 222
    invoke-static {v11, v12, v13}, Llp/yc;->a(ID)D

    .line 223
    .line 224
    .line 225
    move-result-wide v12

    .line 226
    cmpg-double v11, v25, v12

    .line 227
    .line 228
    if-gtz v11, :cond_4

    .line 229
    .line 230
    const/4 v11, 0x1

    .line 231
    goto :goto_2

    .line 232
    :cond_4
    const/4 v11, 0x0

    .line 233
    :goto_2
    if-nez v10, :cond_5

    .line 234
    .line 235
    const/4 v12, 0x1

    .line 236
    goto :goto_3

    .line 237
    :cond_5
    const/4 v12, 0x0

    .line 238
    :goto_3
    add-int/lit8 v13, v4, -0x2

    .line 239
    .line 240
    if-ne v10, v13, :cond_6

    .line 241
    .line 242
    const/4 v13, 0x1

    .line 243
    goto :goto_4

    .line 244
    :cond_6
    const/4 v13, 0x0

    .line 245
    :goto_4
    if-eqz v12, :cond_7

    .line 246
    .line 247
    cmpg-double v2, v2, v17

    .line 248
    .line 249
    if-gtz v2, :cond_7

    .line 250
    .line 251
    const/4 v2, 0x1

    .line 252
    goto :goto_5

    .line 253
    :cond_7
    const/4 v2, 0x0

    .line 254
    :goto_5
    if-eqz v13, :cond_8

    .line 255
    .line 256
    cmpg-double v3, v14, v17

    .line 257
    .line 258
    if-gtz v3, :cond_8

    .line 259
    .line 260
    const/4 v3, 0x1

    .line 261
    goto :goto_6

    .line 262
    :cond_8
    const/4 v3, 0x0

    .line 263
    :goto_6
    if-nez v11, :cond_b

    .line 264
    .line 265
    if-nez v2, :cond_b

    .line 266
    .line 267
    if-eqz v3, :cond_9

    .line 268
    .line 269
    goto :goto_8

    .line 270
    :cond_9
    :goto_7
    add-int/lit8 v10, v10, 0x1

    .line 271
    .line 272
    move/from16 v13, v22

    .line 273
    .line 274
    move-object/from16 v3, v23

    .line 275
    .line 276
    move-object/from16 v2, v24

    .line 277
    .line 278
    goto/16 :goto_0

    .line 279
    .line 280
    :cond_a
    move/from16 v10, v16

    .line 281
    .line 282
    :cond_b
    :goto_8
    invoke-virtual {v0, v10}, Leb/j0;->F(I)Z

    .line 283
    .line 284
    .line 285
    move-result v2

    .line 286
    if-eqz v2, :cond_c

    .line 287
    .line 288
    invoke-interface {v1}, Lv71/h;->a()Z

    .line 289
    .line 290
    .line 291
    move-result v2

    .line 292
    if-nez v2, :cond_c

    .line 293
    .line 294
    invoke-interface {v1}, Lv71/h;->b()Ls71/o;

    .line 295
    .line 296
    .line 297
    move-result-object v2

    .line 298
    sget-object v3, Ls71/o;->g:Ls71/o;

    .line 299
    .line 300
    if-ne v2, v3, :cond_d

    .line 301
    .line 302
    :cond_c
    :goto_9
    move-object/from16 v28, v5

    .line 303
    .line 304
    move-object/from16 v31, v6

    .line 305
    .line 306
    goto/16 :goto_1d

    .line 307
    .line 308
    :cond_d
    iget-object v2, v0, Leb/j0;->f:Ljava/lang/Object;

    .line 309
    .line 310
    check-cast v2, Ljava/util/List;

    .line 311
    .line 312
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 313
    .line 314
    .line 315
    move-result v2

    .line 316
    if-eqz v2, :cond_e

    .line 317
    .line 318
    invoke-virtual {v0, v1, v10}, Leb/j0;->j(Lv71/h;I)Ljava/util/ArrayList;

    .line 319
    .line 320
    .line 321
    move-result-object v2

    .line 322
    iput-object v2, v0, Leb/j0;->f:Ljava/lang/Object;

    .line 323
    .line 324
    :cond_e
    iget-object v2, v0, Leb/j0;->e:Ljava/lang/Object;

    .line 325
    .line 326
    check-cast v2, Ljava/util/List;

    .line 327
    .line 328
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 329
    .line 330
    .line 331
    move-result v2

    .line 332
    if-eqz v2, :cond_f

    .line 333
    .line 334
    invoke-virtual {v0}, Leb/j0;->v()Ll71/z;

    .line 335
    .line 336
    .line 337
    move-result-object v2

    .line 338
    iget-object v2, v2, Ll71/z;->b:Lv71/e;

    .line 339
    .line 340
    iget-object v3, v0, Leb/j0;->f:Ljava/lang/Object;

    .line 341
    .line 342
    check-cast v3, Ljava/util/List;

    .line 343
    .line 344
    invoke-virtual {v0, v1, v2, v3}, Leb/j0;->p(Lv71/h;Lv71/e;Ljava/util/List;)Ljava/util/ArrayList;

    .line 345
    .line 346
    .line 347
    move-result-object v2

    .line 348
    iput-object v2, v0, Leb/j0;->e:Ljava/lang/Object;

    .line 349
    .line 350
    :cond_f
    iget-object v2, v0, Leb/j0;->f:Ljava/lang/Object;

    .line 351
    .line 352
    check-cast v2, Ljava/util/List;

    .line 353
    .line 354
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 355
    .line 356
    .line 357
    move-result v2

    .line 358
    add-int/lit8 v3, v4, -0x1

    .line 359
    .line 360
    if-lt v2, v3, :cond_c

    .line 361
    .line 362
    iget-object v2, v0, Leb/j0;->e:Ljava/lang/Object;

    .line 363
    .line 364
    check-cast v2, Ljava/util/List;

    .line 365
    .line 366
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 367
    .line 368
    .line 369
    move-result v2

    .line 370
    if-ge v2, v4, :cond_10

    .line 371
    .line 372
    goto :goto_9

    .line 373
    :cond_10
    iget-object v2, v0, Leb/j0;->f:Ljava/lang/Object;

    .line 374
    .line 375
    check-cast v2, Ljava/util/List;

    .line 376
    .line 377
    iget-object v3, v0, Leb/j0;->e:Ljava/lang/Object;

    .line 378
    .line 379
    check-cast v3, Ljava/util/List;

    .line 380
    .line 381
    move v4, v10

    .line 382
    invoke-virtual/range {v0 .. v5}, Leb/j0;->u(Lv71/h;Ljava/util/List;Ljava/util/List;ILv71/f;)Llx0/l;

    .line 383
    .line 384
    .line 385
    move-result-object v2

    .line 386
    iget-object v1, v2, Llx0/l;->d:Ljava/lang/Object;

    .line 387
    .line 388
    check-cast v1, Ljava/util/List;

    .line 389
    .line 390
    iget-object v2, v2, Llx0/l;->e:Ljava/lang/Object;

    .line 391
    .line 392
    check-cast v2, Ljava/util/List;

    .line 393
    .line 394
    move-object v3, v1

    .line 395
    check-cast v3, Ljava/util/Collection;

    .line 396
    .line 397
    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    .line 398
    .line 399
    .line 400
    move-result v3

    .line 401
    if-nez v3, :cond_c

    .line 402
    .line 403
    move-object v3, v2

    .line 404
    check-cast v3, Ljava/util/Collection;

    .line 405
    .line 406
    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    .line 407
    .line 408
    .line 409
    move-result v3

    .line 410
    if-nez v3, :cond_c

    .line 411
    .line 412
    const/4 v3, 0x0

    .line 413
    invoke-interface {v2, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 414
    .line 415
    .line 416
    move-result-object v4

    .line 417
    check-cast v4, Lv71/f;

    .line 418
    .line 419
    const/4 v3, 0x1

    .line 420
    invoke-static {v3, v2}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 421
    .line 422
    .line 423
    move-result-object v8

    .line 424
    check-cast v8, Lv71/f;

    .line 425
    .line 426
    invoke-virtual {v0, v7, v4, v8}, Leb/j0;->G(Ls71/o;Lv71/f;Lv71/f;)Ls71/o;

    .line 427
    .line 428
    .line 429
    move-result-object v3

    .line 430
    iput-object v3, v0, Leb/j0;->g:Ljava/lang/Object;

    .line 431
    .line 432
    invoke-virtual {v0, v3}, Leb/j0;->H(Ls71/o;)Z

    .line 433
    .line 434
    .line 435
    move-result v3

    .line 436
    invoke-virtual {v0}, Leb/j0;->v()Ll71/z;

    .line 437
    .line 438
    .line 439
    move-result-object v4

    .line 440
    iget-wide v7, v4, Ll71/z;->a:D

    .line 441
    .line 442
    const-string v4, "relevantSegmentCenters"

    .line 443
    .line 444
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 445
    .line 446
    .line 447
    new-instance v4, Ljava/util/LinkedHashSet;

    .line 448
    .line 449
    invoke-direct {v4}, Ljava/util/LinkedHashSet;-><init>()V

    .line 450
    .line 451
    .line 452
    new-instance v10, Ljava/util/LinkedHashSet;

    .line 453
    .line 454
    invoke-direct {v10}, Ljava/util/LinkedHashSet;-><init>()V

    .line 455
    .line 456
    .line 457
    move-object v12, v1

    .line 458
    check-cast v12, Ljava/util/Collection;

    .line 459
    .line 460
    invoke-interface {v12}, Ljava/util/Collection;->size()I

    .line 461
    .line 462
    .line 463
    move-result v12

    .line 464
    sget-object v13, Lmx0/s;->d:Lmx0/s;

    .line 465
    .line 466
    move-object v15, v13

    .line 467
    const/4 v14, 0x0

    .line 468
    :goto_a
    if-ge v14, v12, :cond_20

    .line 469
    .line 470
    add-int/lit8 v11, v14, 0x1

    .line 471
    .line 472
    move/from16 v22, v3

    .line 473
    .line 474
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 475
    .line 476
    .line 477
    move-result v3

    .line 478
    if-ge v11, v3, :cond_1f

    .line 479
    .line 480
    if-eqz v22, :cond_11

    .line 481
    .line 482
    new-instance v3, Llx0/l;

    .line 483
    .line 484
    move/from16 v23, v12

    .line 485
    .line 486
    invoke-interface {v2, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 487
    .line 488
    .line 489
    move-result-object v12

    .line 490
    move-object/from16 v24, v13

    .line 491
    .line 492
    invoke-interface {v2, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 493
    .line 494
    .line 495
    move-result-object v13

    .line 496
    invoke-direct {v3, v12, v13}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 497
    .line 498
    .line 499
    goto :goto_b

    .line 500
    :cond_11
    move/from16 v23, v12

    .line 501
    .line 502
    move-object/from16 v24, v13

    .line 503
    .line 504
    new-instance v3, Llx0/l;

    .line 505
    .line 506
    invoke-interface {v2, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 507
    .line 508
    .line 509
    move-result-object v12

    .line 510
    invoke-interface {v2, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 511
    .line 512
    .line 513
    move-result-object v13

    .line 514
    invoke-direct {v3, v12, v13}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 515
    .line 516
    .line 517
    :goto_b
    iget-object v12, v3, Llx0/l;->d:Ljava/lang/Object;

    .line 518
    .line 519
    check-cast v12, Lv71/f;

    .line 520
    .line 521
    iget-object v3, v3, Llx0/l;->e:Ljava/lang/Object;

    .line 522
    .line 523
    check-cast v3, Lv71/f;

    .line 524
    .line 525
    invoke-interface {v1, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 526
    .line 527
    .line 528
    move-result-object v13

    .line 529
    check-cast v13, Lw71/c;

    .line 530
    .line 531
    const-string v14, "segmentCenter"

    .line 532
    .line 533
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 534
    .line 535
    .line 536
    invoke-static {v12, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 537
    .line 538
    .line 539
    const-string v14, "nextVehiclePosition"

    .line 540
    .line 541
    invoke-static {v3, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 542
    .line 543
    .line 544
    iget-object v14, v3, Lv71/f;->f:Lv71/g;

    .line 545
    .line 546
    move-object/from16 v25, v1

    .line 547
    .line 548
    iget-object v1, v3, Lv71/f;->d:Lv71/g;

    .line 549
    .line 550
    move-object/from16 v26, v2

    .line 551
    .line 552
    iget-wide v2, v3, Lv71/f;->b:D

    .line 553
    .line 554
    move-wide/from16 v27, v2

    .line 555
    .line 556
    iget-object v2, v12, Lv71/f;->d:Lv71/g;

    .line 557
    .line 558
    iget-object v3, v12, Lv71/f;->f:Lv71/g;

    .line 559
    .line 560
    move-object/from16 v29, v9

    .line 561
    .line 562
    iget-object v9, v12, Lv71/f;->e:Lv71/g;

    .line 563
    .line 564
    move/from16 v30, v11

    .line 565
    .line 566
    iget-wide v11, v12, Lv71/f;->b:D

    .line 567
    .line 568
    sub-double v11, v27, v11

    .line 569
    .line 570
    const-wide/16 v27, 0x0

    .line 571
    .line 572
    cmpg-double v27, v11, v27

    .line 573
    .line 574
    if-gez v27, :cond_12

    .line 575
    .line 576
    const-wide v27, 0x401921fb54442d18L    # 6.283185307179586

    .line 577
    .line 578
    .line 579
    .line 580
    .line 581
    add-double v11, v11, v27

    .line 582
    .line 583
    :cond_12
    const-wide v27, 0x3f847ae147ae147bL    # 0.01

    .line 584
    .line 585
    .line 586
    .line 587
    .line 588
    cmpg-double v27, v11, v27

    .line 589
    .line 590
    if-ltz v27, :cond_14

    .line 591
    .line 592
    const-wide v27, 0x401917bde3a0560eL    # 6.2731853071795864

    .line 593
    .line 594
    .line 595
    .line 596
    .line 597
    cmpl-double v27, v11, v27

    .line 598
    .line 599
    if-lez v27, :cond_13

    .line 600
    .line 601
    goto :goto_c

    .line 602
    :cond_13
    const/16 v27, 0x0

    .line 603
    .line 604
    goto :goto_d

    .line 605
    :cond_14
    :goto_c
    const/16 v27, 0x1

    .line 606
    .line 607
    :goto_d
    const-wide v31, 0x400921fb54442d18L    # Math.PI

    .line 608
    .line 609
    .line 610
    .line 611
    .line 612
    cmpl-double v11, v11, v31

    .line 613
    .line 614
    if-lez v11, :cond_15

    .line 615
    .line 616
    const/4 v11, 0x1

    .line 617
    goto :goto_e

    .line 618
    :cond_15
    const/4 v11, 0x0

    .line 619
    :goto_e
    if-eqz v27, :cond_16

    .line 620
    .line 621
    new-instance v2, Lv71/d;

    .line 622
    .line 623
    iget-object v3, v9, Lv71/g;->a:Lw71/c;

    .line 624
    .line 625
    iget-object v11, v1, Lv71/g;->a:Lw71/c;

    .line 626
    .line 627
    filled-new-array {v3, v11}, [Lw71/c;

    .line 628
    .line 629
    .line 630
    move-result-object v3

    .line 631
    invoke-static {v3}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 632
    .line 633
    .line 634
    move-result-object v3

    .line 635
    iget-object v1, v1, Lv71/g;->b:Lw71/c;

    .line 636
    .line 637
    iget-object v9, v9, Lv71/g;->b:Lw71/c;

    .line 638
    .line 639
    filled-new-array {v1, v9}, [Lw71/c;

    .line 640
    .line 641
    .line 642
    move-result-object v1

    .line 643
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 644
    .line 645
    .line 646
    move-result-object v1

    .line 647
    invoke-direct {v2, v3, v1}, Lv71/d;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 648
    .line 649
    .line 650
    move-object/from16 v28, v5

    .line 651
    .line 652
    move-object/from16 v31, v6

    .line 653
    .line 654
    move-object/from16 v27, v15

    .line 655
    .line 656
    goto/16 :goto_f

    .line 657
    .line 658
    :cond_16
    if-eqz v11, :cond_17

    .line 659
    .line 660
    new-instance v11, Ljava/util/ArrayList;

    .line 661
    .line 662
    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    .line 663
    .line 664
    .line 665
    new-instance v12, Ljava/util/ArrayList;

    .line 666
    .line 667
    invoke-direct {v12}, Ljava/util/ArrayList;-><init>()V

    .line 668
    .line 669
    .line 670
    move-object/from16 v27, v15

    .line 671
    .line 672
    iget-object v15, v3, Lv71/g;->a:Lw71/c;

    .line 673
    .line 674
    move-object/from16 v28, v5

    .line 675
    .line 676
    iget-object v5, v9, Lv71/g;->a:Lw71/c;

    .line 677
    .line 678
    move-object/from16 v31, v6

    .line 679
    .line 680
    iget-object v6, v9, Lv71/g;->a:Lw71/c;

    .line 681
    .line 682
    invoke-static {v15, v5}, Lw71/d;->f(Lw71/c;Lw71/c;)Lw71/c;

    .line 683
    .line 684
    .line 685
    move-result-object v5

    .line 686
    invoke-static {v15, v5}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 687
    .line 688
    .line 689
    move-result-object v5

    .line 690
    invoke-virtual {v11, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 691
    .line 692
    .line 693
    invoke-static {v13, v6, v5, v7, v8}, Llp/cb;->a(Lw71/c;Lw71/c;Lw71/c;D)Ljava/util/ArrayList;

    .line 694
    .line 695
    .line 696
    move-result-object v5

    .line 697
    invoke-virtual {v11, v5}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 698
    .line 699
    .line 700
    iget-object v5, v2, Lv71/g;->a:Lw71/c;

    .line 701
    .line 702
    invoke-virtual {v11, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 703
    .line 704
    .line 705
    iget-object v2, v2, Lv71/g;->a:Lw71/c;

    .line 706
    .line 707
    iget-object v5, v1, Lv71/g;->a:Lw71/c;

    .line 708
    .line 709
    invoke-static {v13, v2, v5, v7, v8}, Llp/cb;->a(Lw71/c;Lw71/c;Lw71/c;D)Ljava/util/ArrayList;

    .line 710
    .line 711
    .line 712
    move-result-object v2

    .line 713
    invoke-virtual {v11, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 714
    .line 715
    .line 716
    iget-object v1, v1, Lv71/g;->b:Lw71/c;

    .line 717
    .line 718
    invoke-virtual {v12, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 719
    .line 720
    .line 721
    iget-object v1, v14, Lv71/g;->b:Lw71/c;

    .line 722
    .line 723
    invoke-virtual {v12, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 724
    .line 725
    .line 726
    iget-object v1, v14, Lv71/g;->b:Lw71/c;

    .line 727
    .line 728
    iget-object v2, v3, Lv71/g;->b:Lw71/c;

    .line 729
    .line 730
    invoke-static {v13, v1, v2, v7, v8}, Llp/cb;->a(Lw71/c;Lw71/c;Lw71/c;D)Ljava/util/ArrayList;

    .line 731
    .line 732
    .line 733
    move-result-object v1

    .line 734
    invoke-virtual {v12, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 735
    .line 736
    .line 737
    iget-object v1, v9, Lv71/g;->b:Lw71/c;

    .line 738
    .line 739
    invoke-virtual {v12, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 740
    .line 741
    .line 742
    new-instance v2, Lv71/d;

    .line 743
    .line 744
    invoke-static {v11}, Lmx0/q;->g0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 745
    .line 746
    .line 747
    move-result-object v1

    .line 748
    invoke-static {v12}, Lmx0/q;->g0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 749
    .line 750
    .line 751
    move-result-object v3

    .line 752
    invoke-direct {v2, v1, v3}, Lv71/d;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 753
    .line 754
    .line 755
    goto :goto_f

    .line 756
    :cond_17
    move-object/from16 v28, v5

    .line 757
    .line 758
    move-object/from16 v31, v6

    .line 759
    .line 760
    move-object/from16 v27, v15

    .line 761
    .line 762
    new-instance v5, Ljava/util/ArrayList;

    .line 763
    .line 764
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 765
    .line 766
    .line 767
    new-instance v6, Ljava/util/ArrayList;

    .line 768
    .line 769
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 770
    .line 771
    .line 772
    iget-object v11, v3, Lv71/g;->b:Lw71/c;

    .line 773
    .line 774
    iget-object v12, v9, Lv71/g;->b:Lw71/c;

    .line 775
    .line 776
    iget-object v15, v9, Lv71/g;->b:Lw71/c;

    .line 777
    .line 778
    invoke-static {v11, v12}, Lw71/d;->f(Lw71/c;Lw71/c;)Lw71/c;

    .line 779
    .line 780
    .line 781
    move-result-object v12

    .line 782
    invoke-static {v11, v12}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 783
    .line 784
    .line 785
    move-result-object v11

    .line 786
    invoke-virtual {v6, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 787
    .line 788
    .line 789
    invoke-static {v13, v15, v11, v7, v8}, Llp/cb;->a(Lw71/c;Lw71/c;Lw71/c;D)Ljava/util/ArrayList;

    .line 790
    .line 791
    .line 792
    move-result-object v11

    .line 793
    invoke-virtual {v6, v11}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 794
    .line 795
    .line 796
    iget-object v11, v2, Lv71/g;->b:Lw71/c;

    .line 797
    .line 798
    invoke-virtual {v6, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 799
    .line 800
    .line 801
    iget-object v2, v2, Lv71/g;->b:Lw71/c;

    .line 802
    .line 803
    iget-object v11, v1, Lv71/g;->b:Lw71/c;

    .line 804
    .line 805
    invoke-static {v13, v2, v11, v7, v8}, Llp/cb;->a(Lw71/c;Lw71/c;Lw71/c;D)Ljava/util/ArrayList;

    .line 806
    .line 807
    .line 808
    move-result-object v2

    .line 809
    invoke-virtual {v6, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 810
    .line 811
    .line 812
    iget-object v1, v1, Lv71/g;->a:Lw71/c;

    .line 813
    .line 814
    invoke-virtual {v5, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 815
    .line 816
    .line 817
    iget-object v1, v14, Lv71/g;->a:Lw71/c;

    .line 818
    .line 819
    invoke-virtual {v5, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 820
    .line 821
    .line 822
    iget-object v1, v14, Lv71/g;->a:Lw71/c;

    .line 823
    .line 824
    iget-object v2, v3, Lv71/g;->a:Lw71/c;

    .line 825
    .line 826
    invoke-static {v13, v1, v2, v7, v8}, Llp/cb;->a(Lw71/c;Lw71/c;Lw71/c;D)Ljava/util/ArrayList;

    .line 827
    .line 828
    .line 829
    move-result-object v1

    .line 830
    invoke-virtual {v5, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 831
    .line 832
    .line 833
    iget-object v1, v9, Lv71/g;->a:Lw71/c;

    .line 834
    .line 835
    invoke-virtual {v5, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 836
    .line 837
    .line 838
    new-instance v2, Lv71/d;

    .line 839
    .line 840
    invoke-direct {v2, v5, v6}, Lv71/d;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 841
    .line 842
    .line 843
    :goto_f
    iget-object v1, v2, Lv71/d;->a:Ljava/util/List;

    .line 844
    .line 845
    move-object v3, v1

    .line 846
    check-cast v3, Ljava/lang/Iterable;

    .line 847
    .line 848
    new-instance v5, Ljava/util/ArrayList;

    .line 849
    .line 850
    const/16 v6, 0xa

    .line 851
    .line 852
    invoke-static {v3, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 853
    .line 854
    .line 855
    move-result v9

    .line 856
    invoke-direct {v5, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 857
    .line 858
    .line 859
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 860
    .line 861
    .line 862
    move-result-object v3

    .line 863
    :goto_10
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 864
    .line 865
    .line 866
    move-result v6

    .line 867
    if-eqz v6, :cond_18

    .line 868
    .line 869
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 870
    .line 871
    .line 872
    move-result-object v6

    .line 873
    check-cast v6, Lw71/c;

    .line 874
    .line 875
    const/4 v11, 0x5

    .line 876
    invoke-static {v6, v11}, Lw71/d;->i(Lw71/c;I)Lw71/c;

    .line 877
    .line 878
    .line 879
    move-result-object v6

    .line 880
    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 881
    .line 882
    .line 883
    goto :goto_10

    .line 884
    :cond_18
    iget-object v2, v2, Lv71/d;->b:Ljava/util/List;

    .line 885
    .line 886
    move-object v3, v2

    .line 887
    check-cast v3, Ljava/lang/Iterable;

    .line 888
    .line 889
    new-instance v5, Ljava/util/ArrayList;

    .line 890
    .line 891
    const/16 v6, 0xa

    .line 892
    .line 893
    invoke-static {v3, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 894
    .line 895
    .line 896
    move-result v9

    .line 897
    invoke-direct {v5, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 898
    .line 899
    .line 900
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 901
    .line 902
    .line 903
    move-result-object v6

    .line 904
    :goto_11
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 905
    .line 906
    .line 907
    move-result v9

    .line 908
    if-eqz v9, :cond_19

    .line 909
    .line 910
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 911
    .line 912
    .line 913
    move-result-object v9

    .line 914
    check-cast v9, Lw71/c;

    .line 915
    .line 916
    const/4 v11, 0x5

    .line 917
    invoke-static {v9, v11}, Lw71/d;->i(Lw71/c;I)Lw71/c;

    .line 918
    .line 919
    .line 920
    move-result-object v9

    .line 921
    invoke-virtual {v5, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 922
    .line 923
    .line 924
    goto :goto_11

    .line 925
    :cond_19
    const/4 v11, 0x5

    .line 926
    check-cast v1, Ljava/util/Collection;

    .line 927
    .line 928
    invoke-interface {v10, v1}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    .line 929
    .line 930
    .line 931
    check-cast v2, Ljava/util/Collection;

    .line 932
    .line 933
    invoke-interface {v4, v2}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    .line 934
    .line 935
    .line 936
    invoke-static {v3, v1}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 937
    .line 938
    .line 939
    move-result-object v1

    .line 940
    move-object/from16 v15, v27

    .line 941
    .line 942
    check-cast v15, Ljava/lang/Iterable;

    .line 943
    .line 944
    new-instance v2, Ljava/util/ArrayList;

    .line 945
    .line 946
    const/16 v6, 0xa

    .line 947
    .line 948
    invoke-static {v15, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 949
    .line 950
    .line 951
    move-result v3

    .line 952
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 953
    .line 954
    .line 955
    invoke-interface {v15}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 956
    .line 957
    .line 958
    move-result-object v3

    .line 959
    :goto_12
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 960
    .line 961
    .line 962
    move-result v5

    .line 963
    const-string v6, "<this>"

    .line 964
    .line 965
    if-eqz v5, :cond_1a

    .line 966
    .line 967
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 968
    .line 969
    .line 970
    move-result-object v5

    .line 971
    check-cast v5, Lw71/c;

    .line 972
    .line 973
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 974
    .line 975
    .line 976
    new-instance v6, Lx71/h;

    .line 977
    .line 978
    iget-wide v12, v5, Lw71/c;->a:D

    .line 979
    .line 980
    sget-wide v14, Lw71/d;->a:D

    .line 981
    .line 982
    mul-double/2addr v12, v14

    .line 983
    invoke-static {v12, v13}, Lcy0/a;->j(D)J

    .line 984
    .line 985
    .line 986
    move-result-wide v12

    .line 987
    move-wide/from16 v32, v12

    .line 988
    .line 989
    iget-wide v11, v5, Lw71/c;->b:D

    .line 990
    .line 991
    mul-double/2addr v11, v14

    .line 992
    invoke-static {v11, v12}, Lcy0/a;->j(D)J

    .line 993
    .line 994
    .line 995
    move-result-wide v11

    .line 996
    move-wide/from16 v13, v32

    .line 997
    .line 998
    invoke-direct {v6, v13, v14, v11, v12}, Lx71/h;-><init>(JJ)V

    .line 999
    .line 1000
    .line 1001
    invoke-virtual {v2, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1002
    .line 1003
    .line 1004
    const/4 v11, 0x5

    .line 1005
    goto :goto_12

    .line 1006
    :cond_1a
    invoke-static {v2}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 1007
    .line 1008
    .line 1009
    move-result-object v2

    .line 1010
    new-instance v3, Ljava/util/ArrayList;

    .line 1011
    .line 1012
    const/16 v5, 0xa

    .line 1013
    .line 1014
    invoke-static {v1, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1015
    .line 1016
    .line 1017
    move-result v9

    .line 1018
    invoke-direct {v3, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 1019
    .line 1020
    .line 1021
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1022
    .line 1023
    .line 1024
    move-result-object v1

    .line 1025
    :goto_13
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1026
    .line 1027
    .line 1028
    move-result v5

    .line 1029
    if-eqz v5, :cond_1b

    .line 1030
    .line 1031
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1032
    .line 1033
    .line 1034
    move-result-object v5

    .line 1035
    check-cast v5, Lw71/c;

    .line 1036
    .line 1037
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1038
    .line 1039
    .line 1040
    new-instance v9, Lx71/h;

    .line 1041
    .line 1042
    iget-wide v11, v5, Lw71/c;->a:D

    .line 1043
    .line 1044
    sget-wide v13, Lw71/d;->a:D

    .line 1045
    .line 1046
    mul-double/2addr v11, v13

    .line 1047
    invoke-static {v11, v12}, Lcy0/a;->j(D)J

    .line 1048
    .line 1049
    .line 1050
    move-result-wide v11

    .line 1051
    move-wide/from16 v32, v7

    .line 1052
    .line 1053
    iget-wide v7, v5, Lw71/c;->b:D

    .line 1054
    .line 1055
    mul-double/2addr v7, v13

    .line 1056
    invoke-static {v7, v8}, Lcy0/a;->j(D)J

    .line 1057
    .line 1058
    .line 1059
    move-result-wide v7

    .line 1060
    invoke-direct {v9, v11, v12, v7, v8}, Lx71/h;-><init>(JJ)V

    .line 1061
    .line 1062
    .line 1063
    invoke-virtual {v3, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1064
    .line 1065
    .line 1066
    move-wide/from16 v7, v32

    .line 1067
    .line 1068
    goto :goto_13

    .line 1069
    :cond_1b
    move-wide/from16 v32, v7

    .line 1070
    .line 1071
    invoke-static {v3}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 1072
    .line 1073
    .line 1074
    move-result-object v1

    .line 1075
    new-instance v3, Lx71/c;

    .line 1076
    .line 1077
    invoke-direct {v3}, Lx71/c;-><init>()V

    .line 1078
    .line 1079
    .line 1080
    sget-object v5, Lx71/m;->d:Lx71/m;

    .line 1081
    .line 1082
    invoke-virtual {v3, v2, v5}, Lx71/c;->e(Ljava/util/ArrayList;Lx71/m;)V

    .line 1083
    .line 1084
    .line 1085
    sget-object v2, Lx71/m;->e:Lx71/m;

    .line 1086
    .line 1087
    invoke-virtual {v3, v1, v2}, Lx71/c;->e(Ljava/util/ArrayList;Lx71/m;)V

    .line 1088
    .line 1089
    .line 1090
    new-instance v1, Ljava/util/ArrayList;

    .line 1091
    .line 1092
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 1093
    .line 1094
    .line 1095
    sget-object v2, Lx71/a;->d:Lx71/a;

    .line 1096
    .line 1097
    sget-object v5, Lx71/l;->e:Lx71/l;

    .line 1098
    .line 1099
    iget-boolean v7, v3, Lx71/c;->n:Z

    .line 1100
    .line 1101
    if-eqz v7, :cond_1c

    .line 1102
    .line 1103
    const/4 v7, 0x1

    .line 1104
    goto :goto_15

    .line 1105
    :cond_1c
    const/4 v7, 0x1

    .line 1106
    iput-boolean v7, v3, Lx71/c;->n:Z

    .line 1107
    .line 1108
    invoke-virtual {v1}, Ljava/util/ArrayList;->clear()V

    .line 1109
    .line 1110
    .line 1111
    iput-object v5, v3, Lx71/c;->p:Lx71/l;

    .line 1112
    .line 1113
    iput-object v5, v3, Lx71/c;->o:Lx71/l;

    .line 1114
    .line 1115
    iput-object v2, v3, Lx71/c;->i:Lx71/a;

    .line 1116
    .line 1117
    :try_start_0
    invoke-virtual {v3}, Lx71/c;->n()Z

    .line 1118
    .line 1119
    .line 1120
    move-result v2

    .line 1121
    if-eqz v2, :cond_1d

    .line 1122
    .line 1123
    invoke-virtual {v3, v1}, Lx71/c;->h(Ljava/util/ArrayList;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 1124
    .line 1125
    .line 1126
    goto :goto_14

    .line 1127
    :catchall_0
    move-exception v0

    .line 1128
    goto :goto_17

    .line 1129
    :cond_1d
    :goto_14
    iget-object v2, v3, Lx71/c;->e:Ljava/util/ArrayList;

    .line 1130
    .line 1131
    invoke-virtual {v2}, Ljava/util/ArrayList;->clear()V

    .line 1132
    .line 1133
    .line 1134
    const/4 v2, 0x0

    .line 1135
    iput-boolean v2, v3, Lx71/c;->n:Z

    .line 1136
    .line 1137
    :goto_15
    invoke-static {v1}, Lmx0/o;->t(Ljava/lang/Iterable;)Ljava/util/ArrayList;

    .line 1138
    .line 1139
    .line 1140
    move-result-object v1

    .line 1141
    new-instance v15, Ljava/util/ArrayList;

    .line 1142
    .line 1143
    const/16 v5, 0xa

    .line 1144
    .line 1145
    invoke-static {v1, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1146
    .line 1147
    .line 1148
    move-result v2

    .line 1149
    invoke-direct {v15, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 1150
    .line 1151
    .line 1152
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1153
    .line 1154
    .line 1155
    move-result-object v1

    .line 1156
    :goto_16
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1157
    .line 1158
    .line 1159
    move-result v2

    .line 1160
    if-eqz v2, :cond_1e

    .line 1161
    .line 1162
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1163
    .line 1164
    .line 1165
    move-result-object v2

    .line 1166
    check-cast v2, Lx71/h;

    .line 1167
    .line 1168
    sget v3, Lw71/d;->b:I

    .line 1169
    .line 1170
    invoke-static {v2, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1171
    .line 1172
    .line 1173
    new-instance v3, Lw71/c;

    .line 1174
    .line 1175
    iget-wide v8, v2, Lx71/h;->a:J

    .line 1176
    .line 1177
    long-to-double v8, v8

    .line 1178
    sget-wide v11, Lw71/d;->a:D

    .line 1179
    .line 1180
    div-double/2addr v8, v11

    .line 1181
    iget-wide v13, v2, Lx71/h;->b:J

    .line 1182
    .line 1183
    long-to-double v13, v13

    .line 1184
    div-double/2addr v13, v11

    .line 1185
    invoke-direct {v3, v8, v9, v13, v14}, Lw71/c;-><init>(DD)V

    .line 1186
    .line 1187
    .line 1188
    invoke-virtual {v15, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1189
    .line 1190
    .line 1191
    goto :goto_16

    .line 1192
    :cond_1e
    move/from16 v3, v22

    .line 1193
    .line 1194
    move/from16 v12, v23

    .line 1195
    .line 1196
    move-object/from16 v13, v24

    .line 1197
    .line 1198
    move-object/from16 v1, v25

    .line 1199
    .line 1200
    move-object/from16 v2, v26

    .line 1201
    .line 1202
    move-object/from16 v5, v28

    .line 1203
    .line 1204
    move-object/from16 v9, v29

    .line 1205
    .line 1206
    move/from16 v14, v30

    .line 1207
    .line 1208
    move-object/from16 v6, v31

    .line 1209
    .line 1210
    move-wide/from16 v7, v32

    .line 1211
    .line 1212
    goto/16 :goto_a

    .line 1213
    .line 1214
    :goto_17
    iget-object v1, v3, Lx71/c;->e:Ljava/util/ArrayList;

    .line 1215
    .line 1216
    invoke-virtual {v1}, Ljava/util/ArrayList;->clear()V

    .line 1217
    .line 1218
    .line 1219
    const/4 v2, 0x0

    .line 1220
    iput-boolean v2, v3, Lx71/c;->n:Z

    .line 1221
    .line 1222
    throw v0

    .line 1223
    :cond_1f
    :goto_18
    move-object/from16 v26, v2

    .line 1224
    .line 1225
    move-object/from16 v28, v5

    .line 1226
    .line 1227
    move-object/from16 v31, v6

    .line 1228
    .line 1229
    move-object/from16 v24, v13

    .line 1230
    .line 1231
    move-object/from16 v27, v15

    .line 1232
    .line 1233
    goto :goto_19

    .line 1234
    :cond_20
    move/from16 v22, v3

    .line 1235
    .line 1236
    goto :goto_18

    .line 1237
    :goto_19
    invoke-interface/range {v27 .. v27}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 1238
    .line 1239
    .line 1240
    move-result-object v1

    .line 1241
    move-object/from16 v2, v24

    .line 1242
    .line 1243
    move-object v13, v2

    .line 1244
    :goto_1a
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1245
    .line 1246
    .line 1247
    move-result v3

    .line 1248
    if-eqz v3, :cond_23

    .line 1249
    .line 1250
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1251
    .line 1252
    .line 1253
    move-result-object v3

    .line 1254
    check-cast v3, Lw71/c;

    .line 1255
    .line 1256
    move-wide/from16 v5, v17

    .line 1257
    .line 1258
    invoke-static {v3, v10, v5, v6}, Lw71/d;->e(Lw71/c;Ljava/util/Collection;D)Z

    .line 1259
    .line 1260
    .line 1261
    move-result v7

    .line 1262
    if-eqz v7, :cond_22

    .line 1263
    .line 1264
    invoke-static {v13, v3}, Llp/bd;->a(Ljava/util/List;Lw71/c;)Ljava/util/List;

    .line 1265
    .line 1266
    .line 1267
    move-result-object v13

    .line 1268
    :cond_21
    :goto_1b
    move-wide/from16 v17, v5

    .line 1269
    .line 1270
    goto :goto_1a

    .line 1271
    :cond_22
    invoke-static {v3, v4, v5, v6}, Lw71/d;->e(Lw71/c;Ljava/util/Collection;D)Z

    .line 1272
    .line 1273
    .line 1274
    move-result v7

    .line 1275
    if-eqz v7, :cond_21

    .line 1276
    .line 1277
    invoke-static {v2, v3}, Llp/bd;->a(Ljava/util/List;Lw71/c;)Ljava/util/List;

    .line 1278
    .line 1279
    .line 1280
    move-result-object v2

    .line 1281
    goto :goto_1b

    .line 1282
    :cond_23
    const-string v1, "left"

    .line 1283
    .line 1284
    invoke-static {v13, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1285
    .line 1286
    .line 1287
    const-string v1, "right"

    .line 1288
    .line 1289
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1290
    .line 1291
    .line 1292
    invoke-static/range {v26 .. v26}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 1293
    .line 1294
    .line 1295
    move-result-object v1

    .line 1296
    check-cast v1, Lv71/f;

    .line 1297
    .line 1298
    if-eqz v22, :cond_24

    .line 1299
    .line 1300
    iget-object v1, v1, Lv71/f;->d:Lv71/g;

    .line 1301
    .line 1302
    goto :goto_1c

    .line 1303
    :cond_24
    iget-object v1, v1, Lv71/f;->e:Lv71/g;

    .line 1304
    .line 1305
    :goto_1c
    new-instance v8, Lv71/d;

    .line 1306
    .line 1307
    iget-object v3, v1, Lv71/g;->a:Lw71/c;

    .line 1308
    .line 1309
    check-cast v13, Ljava/lang/Iterable;

    .line 1310
    .line 1311
    new-instance v4, Ld4/b0;

    .line 1312
    .line 1313
    const/4 v5, 0x6

    .line 1314
    invoke-direct {v4, v3, v5}, Ld4/b0;-><init>(Ljava/lang/Object;I)V

    .line 1315
    .line 1316
    .line 1317
    invoke-static {v13, v4}, Lmx0/q;->p0(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    .line 1318
    .line 1319
    .line 1320
    move-result-object v3

    .line 1321
    iget-object v1, v1, Lv71/g;->b:Lw71/c;

    .line 1322
    .line 1323
    check-cast v2, Ljava/lang/Iterable;

    .line 1324
    .line 1325
    new-instance v4, Ld4/b0;

    .line 1326
    .line 1327
    invoke-direct {v4, v1, v5}, Ld4/b0;-><init>(Ljava/lang/Object;I)V

    .line 1328
    .line 1329
    .line 1330
    invoke-static {v2, v4}, Lmx0/q;->p0(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    .line 1331
    .line 1332
    .line 1333
    move-result-object v1

    .line 1334
    invoke-direct {v8, v3, v1}, Lv71/d;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 1335
    .line 1336
    .line 1337
    :goto_1d
    invoke-interface/range {p1 .. p1}, Lv71/h;->c()Z

    .line 1338
    .line 1339
    .line 1340
    move-result v1

    .line 1341
    invoke-interface/range {p1 .. p1}, Lv71/h;->a()Z

    .line 1342
    .line 1343
    .line 1344
    move-result v2

    .line 1345
    iget-object v3, v0, Leb/j0;->g:Ljava/lang/Object;

    .line 1346
    .line 1347
    check-cast v3, Ls71/o;

    .line 1348
    .line 1349
    invoke-virtual {v0}, Leb/j0;->v()Ll71/z;

    .line 1350
    .line 1351
    .line 1352
    move-result-object v4

    .line 1353
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1354
    .line 1355
    .line 1356
    iget-object v4, v8, Lv71/d;->b:Ljava/util/List;

    .line 1357
    .line 1358
    iget-object v5, v8, Lv71/d;->a:Ljava/util/List;

    .line 1359
    .line 1360
    if-eqz v1, :cond_25

    .line 1361
    .line 1362
    if-nez v2, :cond_25

    .line 1363
    .line 1364
    sget-object v1, Ls71/o;->g:Ls71/o;

    .line 1365
    .line 1366
    if-eq v3, v1, :cond_25

    .line 1367
    .line 1368
    sget-object v1, Ls71/o;->f:Ls71/o;

    .line 1369
    .line 1370
    if-eq v3, v1, :cond_25

    .line 1371
    .line 1372
    invoke-virtual {v0, v5, v3}, Leb/j0;->s(Ljava/util/List;Ls71/o;)Llx0/l;

    .line 1373
    .line 1374
    .line 1375
    move-result-object v1

    .line 1376
    invoke-virtual {v0, v4, v3}, Leb/j0;->s(Ljava/util/List;Ls71/o;)Llx0/l;

    .line 1377
    .line 1378
    .line 1379
    move-result-object v2

    .line 1380
    if-eqz v1, :cond_25

    .line 1381
    .line 1382
    if-eqz v2, :cond_25

    .line 1383
    .line 1384
    iget-object v3, v1, Llx0/l;->d:Ljava/lang/Object;

    .line 1385
    .line 1386
    check-cast v3, Lw71/c;

    .line 1387
    .line 1388
    iget-object v1, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 1389
    .line 1390
    check-cast v1, Lw71/c;

    .line 1391
    .line 1392
    iget-object v6, v2, Llx0/l;->d:Ljava/lang/Object;

    .line 1393
    .line 1394
    check-cast v6, Lw71/c;

    .line 1395
    .line 1396
    iget-object v2, v2, Llx0/l;->e:Ljava/lang/Object;

    .line 1397
    .line 1398
    check-cast v2, Lw71/c;

    .line 1399
    .line 1400
    invoke-static {v6, v3}, Lw71/d;->f(Lw71/c;Lw71/c;)Lw71/c;

    .line 1401
    .line 1402
    .line 1403
    move-result-object v7

    .line 1404
    iget-wide v9, v7, Lw71/c;->b:D

    .line 1405
    .line 1406
    iget-wide v11, v7, Lw71/c;->a:D

    .line 1407
    .line 1408
    invoke-static {v9, v10, v11, v12}, Ljava/lang/Math;->atan2(DD)D

    .line 1409
    .line 1410
    .line 1411
    move-result-wide v9

    .line 1412
    invoke-static {v6, v3}, Lw71/d;->b(Lw71/c;Lw71/c;)D

    .line 1413
    .line 1414
    .line 1415
    move-result-wide v11

    .line 1416
    invoke-static {v3, v6}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 1417
    .line 1418
    .line 1419
    move-result-object v3

    .line 1420
    new-instance v6, Lw71/c;

    .line 1421
    .line 1422
    iget-wide v13, v3, Lw71/c;->a:D

    .line 1423
    .line 1424
    const/4 v7, 0x2

    .line 1425
    move-object/from16 v25, v8

    .line 1426
    .line 1427
    int-to-double v7, v7

    .line 1428
    div-double/2addr v13, v7

    .line 1429
    move-wide/from16 v17, v7

    .line 1430
    .line 1431
    iget-wide v7, v3, Lw71/c;->b:D

    .line 1432
    .line 1433
    div-double v7, v7, v17

    .line 1434
    .line 1435
    invoke-direct {v6, v13, v14, v7, v8}, Lw71/c;-><init>(DD)V

    .line 1436
    .line 1437
    .line 1438
    invoke-static {v1, v2}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 1439
    .line 1440
    .line 1441
    move-result-object v1

    .line 1442
    new-instance v2, Lw71/c;

    .line 1443
    .line 1444
    iget-wide v7, v1, Lw71/c;->a:D

    .line 1445
    .line 1446
    div-double v7, v7, v17

    .line 1447
    .line 1448
    iget-wide v13, v1, Lw71/c;->b:D

    .line 1449
    .line 1450
    div-double v13, v13, v17

    .line 1451
    .line 1452
    invoke-direct {v2, v7, v8, v13, v14}, Lw71/c;-><init>(DD)V

    .line 1453
    .line 1454
    .line 1455
    invoke-static {v6, v2}, Lw71/d;->f(Lw71/c;Lw71/c;)Lw71/c;

    .line 1456
    .line 1457
    .line 1458
    move-result-object v1

    .line 1459
    invoke-static {v1}, Lw71/d;->g(Lw71/c;)Lw71/c;

    .line 1460
    .line 1461
    .line 1462
    move-result-object v1

    .line 1463
    if-eqz v1, :cond_26

    .line 1464
    .line 1465
    const-wide v2, 0x3fb999999999999aL    # 0.1

    .line 1466
    .line 1467
    .line 1468
    .line 1469
    .line 1470
    invoke-static {v1, v2, v3}, Lw71/d;->j(Lw71/c;D)Lw71/c;

    .line 1471
    .line 1472
    .line 1473
    move-result-object v1

    .line 1474
    invoke-static {v6, v1}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 1475
    .line 1476
    .line 1477
    move-result-object v1

    .line 1478
    new-instance v13, Lv71/a;

    .line 1479
    .line 1480
    new-instance v2, Lw71/b;

    .line 1481
    .line 1482
    const/16 v6, 0xa

    .line 1483
    .line 1484
    invoke-static {v1, v6}, Lw71/d;->i(Lw71/c;I)Lw71/c;

    .line 1485
    .line 1486
    .line 1487
    move-result-object v1

    .line 1488
    invoke-static {v6, v9, v10}, Llp/yc;->a(ID)D

    .line 1489
    .line 1490
    .line 1491
    move-result-wide v7

    .line 1492
    invoke-direct {v2, v1, v7, v8}, Lw71/b;-><init>(Lw71/c;D)V

    .line 1493
    .line 1494
    .line 1495
    invoke-static {v6, v11, v12}, Llp/yc;->a(ID)D

    .line 1496
    .line 1497
    .line 1498
    move-result-wide v6

    .line 1499
    invoke-direct {v13, v2, v6, v7}, Lv71/a;-><init>(Lw71/b;D)V

    .line 1500
    .line 1501
    .line 1502
    move-object/from16 v21, v13

    .line 1503
    .line 1504
    goto :goto_1e

    .line 1505
    :cond_25
    move-object/from16 v25, v8

    .line 1506
    .line 1507
    :cond_26
    const/16 v21, 0x0

    .line 1508
    .line 1509
    :goto_1e
    invoke-static {v5, v4}, Llp/bb;->a(Ljava/util/List;Ljava/util/List;)Lv71/c;

    .line 1510
    .line 1511
    .line 1512
    move-result-object v20

    .line 1513
    new-instance v17, Lv71/b;

    .line 1514
    .line 1515
    move-object/from16 v1, v31

    .line 1516
    .line 1517
    iget-object v2, v1, Lw71/b;->a:Lw71/c;

    .line 1518
    .line 1519
    iget-object v0, v0, Leb/j0;->g:Ljava/lang/Object;

    .line 1520
    .line 1521
    move-object/from16 v22, v0

    .line 1522
    .line 1523
    check-cast v22, Ls71/o;

    .line 1524
    .line 1525
    iget-wide v0, v1, Lw71/b;->b:D

    .line 1526
    .line 1527
    const/16 v26, 0x1

    .line 1528
    .line 1529
    move-object/from16 v5, v28

    .line 1530
    .line 1531
    iget-object v3, v5, Lv71/f;->g:Lw71/c;

    .line 1532
    .line 1533
    move-wide/from16 v23, v0

    .line 1534
    .line 1535
    move-object/from16 v18, v2

    .line 1536
    .line 1537
    move-object/from16 v19, v3

    .line 1538
    .line 1539
    invoke-direct/range {v17 .. v26}, Lv71/b;-><init>(Lw71/c;Lw71/c;Lv71/c;Lv71/a;Ls71/o;DLv71/d;Z)V

    .line 1540
    .line 1541
    .line 1542
    return-object v17
.end method

.method public o()V
    .locals 2

    .line 1
    iget-object v0, p0, Leb/j0;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    add-int/lit8 v1, v1, -0x1

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iput-object v0, p0, Leb/j0;->g:Ljava/lang/Object;

    .line 16
    .line 17
    return-void
.end method

.method public abstract p(Lv71/h;Lv71/e;Ljava/util/List;)Ljava/util/ArrayList;
.end method

.method public q(Ljava/util/concurrent/Executor;Ljava/util/concurrent/Callable;La0/j;)Laq/t;
    .locals 8

    .line 1
    iget-object v0, p0, Leb/j0;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-lez v0, :cond_0

    .line 10
    .line 11
    const/4 v0, 0x1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 v0, 0x0

    .line 14
    :goto_0
    invoke-static {v0}, Lno/c0;->k(Z)V

    .line 15
    .line 16
    .line 17
    iget-object v0, p3, La0/j;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Laq/t;

    .line 20
    .line 21
    invoke-virtual {v0}, Laq/t;->h()Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_1

    .line 26
    .line 27
    new-instance p0, Laq/t;

    .line 28
    .line 29
    invoke-direct {p0}, Laq/t;-><init>()V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0}, Laq/t;->p()V

    .line 33
    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_1
    new-instance v3, Laq/a;

    .line 37
    .line 38
    const/4 v0, 0x0

    .line 39
    invoke-direct {v3, v0}, Laq/a;-><init>(I)V

    .line 40
    .line 41
    .line 42
    new-instance v5, Laq/k;

    .line 43
    .line 44
    iget-object v0, v3, Laq/a;->e:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v0, La0/j;

    .line 47
    .line 48
    invoke-direct {v5, v0}, Laq/k;-><init>(La0/j;)V

    .line 49
    .line 50
    .line 51
    new-instance v7, Lfv/o;

    .line 52
    .line 53
    invoke-direct {v7, p1, p3, v3, v5}, Lfv/o;-><init>(Ljava/util/concurrent/Executor;La0/j;Laq/a;Laq/k;)V

    .line 54
    .line 55
    .line 56
    iget-object p1, p0, Leb/j0;->e:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast p1, La8/b;

    .line 59
    .line 60
    new-instance v0, Lfv/p;

    .line 61
    .line 62
    const/4 v6, 0x0

    .line 63
    move-object v1, p0

    .line 64
    move-object v4, p2

    .line 65
    move-object v2, p3

    .line 66
    invoke-direct/range {v0 .. v6}, Lfv/p;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {p1, v7, v0}, La8/b;->s(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 70
    .line 71
    .line 72
    iget-object p0, v5, Laq/k;->a:Laq/t;

    .line 73
    .line 74
    return-object p0
.end method

.method public r()V
    .locals 1

    .line 1
    iget-object v0, p0, Leb/j0;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Leb/j0;->e:Ljava/lang/Object;

    .line 9
    .line 10
    iput-object v0, p0, Leb/j0;->g:Ljava/lang/Object;

    .line 11
    .line 12
    invoke-virtual {p0}, Leb/j0;->z()V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public abstract s(Ljava/util/List;Ls71/o;)Llx0/l;
.end method

.method public abstract t()Ljava/lang/String;
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget v0, p0, Leb/j0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    iget-object v0, p0, Leb/j0;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Ljava/lang/String;

    .line 14
    .line 15
    iget-object v1, p0, Leb/j0;->f:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v1, Ls41/c;

    .line 18
    .line 19
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    iget-object p0, p0, Leb/j0;->g:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p0, Ljava/util/List;

    .line 26
    .line 27
    const-string v2, ", type: "

    .line 28
    .line 29
    const-string v3, ", callingClass: "

    .line 30
    .line 31
    const-string v4, "TrackableEntity(identifier: "

    .line 32
    .line 33
    invoke-static {v4, v0, v2, v1, v3}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    const/4 v1, 0x0

    .line 38
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v1, ", success: null, error: null, contextData: "

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    const-string p0, ")"

    .line 50
    .line 51
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0

    .line 59
    :pswitch_data_0
    .packed-switch 0x5
        :pswitch_0
    .end packed-switch
.end method

.method public abstract u(Lv71/h;Ljava/util/List;Ljava/util/List;ILv71/f;)Llx0/l;
.end method

.method public abstract v()Ll71/z;
.end method

.method public abstract w()Lmr/a;
.end method

.method public abstract x()V
.end method

.method public abstract z()V
.end method
