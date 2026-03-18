.class public final Lr9/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Z

.field public final d:J

.field public final e:J

.field public final f:Lr9/g;

.field public final g:[Ljava/lang/String;

.field public final h:Ljava/lang/String;

.field public final i:Ljava/lang/String;

.field public final j:Lr9/c;

.field public final k:Ljava/util/HashMap;

.field public final l:Ljava/util/HashMap;

.field public m:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;JJLr9/g;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lr9/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lr9/c;->a:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lr9/c;->b:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p10, p0, Lr9/c;->i:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p7, p0, Lr9/c;->f:Lr9/g;

    .line 11
    .line 12
    iput-object p8, p0, Lr9/c;->g:[Ljava/lang/String;

    .line 13
    .line 14
    if-eqz p2, :cond_0

    .line 15
    .line 16
    const/4 p1, 0x1

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p1, 0x0

    .line 19
    :goto_0
    iput-boolean p1, p0, Lr9/c;->c:Z

    .line 20
    .line 21
    iput-wide p3, p0, Lr9/c;->d:J

    .line 22
    .line 23
    iput-wide p5, p0, Lr9/c;->e:J

    .line 24
    .line 25
    invoke-virtual {p9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    iput-object p9, p0, Lr9/c;->h:Ljava/lang/String;

    .line 29
    .line 30
    iput-object p11, p0, Lr9/c;->j:Lr9/c;

    .line 31
    .line 32
    new-instance p1, Ljava/util/HashMap;

    .line 33
    .line 34
    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    .line 35
    .line 36
    .line 37
    iput-object p1, p0, Lr9/c;->k:Ljava/util/HashMap;

    .line 38
    .line 39
    new-instance p1, Ljava/util/HashMap;

    .line 40
    .line 41
    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    .line 42
    .line 43
    .line 44
    iput-object p1, p0, Lr9/c;->l:Ljava/util/HashMap;

    .line 45
    .line 46
    return-void
.end method

.method public static a(Ljava/lang/String;)Lr9/c;
    .locals 12

    .line 1
    new-instance v0, Lr9/c;

    .line 2
    .line 3
    const-string v1, "\r\n"

    .line 4
    .line 5
    const-string v2, "\n"

    .line 6
    .line 7
    invoke-virtual {p0, v1, v2}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    const-string v1, " *\n *"

    .line 12
    .line 13
    invoke-virtual {p0, v1, v2}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    const-string v1, " "

    .line 18
    .line 19
    invoke-virtual {p0, v2, v1}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    const-string v2, "[ \t\\x0B\u000c\r]+"

    .line 24
    .line 25
    invoke-virtual {p0, v2, v1}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    const/4 v10, 0x0

    .line 30
    const/4 v11, 0x0

    .line 31
    const/4 v1, 0x0

    .line 32
    const-wide v3, -0x7fffffffffffffffL    # -4.9E-324

    .line 33
    .line 34
    .line 35
    .line 36
    .line 37
    const-wide v5, -0x7fffffffffffffffL    # -4.9E-324

    .line 38
    .line 39
    .line 40
    .line 41
    .line 42
    const/4 v7, 0x0

    .line 43
    const/4 v8, 0x0

    .line 44
    const-string v9, ""

    .line 45
    .line 46
    invoke-direct/range {v0 .. v11}, Lr9/c;-><init>(Ljava/lang/String;Ljava/lang/String;JJLr9/g;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lr9/c;)V

    .line 47
    .line 48
    .line 49
    return-object v0
.end method

.method public static e(Ljava/lang/String;Ljava/util/TreeMap;)Landroid/text/SpannableStringBuilder;
    .locals 2

    .line 1
    invoke-virtual {p1, p0}, Ljava/util/TreeMap;->containsKey(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    new-instance v0, Lv7/a;

    .line 8
    .line 9
    invoke-direct {v0}, Lv7/a;-><init>()V

    .line 10
    .line 11
    .line 12
    new-instance v1, Landroid/text/SpannableStringBuilder;

    .line 13
    .line 14
    invoke-direct {v1}, Landroid/text/SpannableStringBuilder;-><init>()V

    .line 15
    .line 16
    .line 17
    iput-object v1, v0, Lv7/a;->a:Ljava/lang/CharSequence;

    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    iput-object v1, v0, Lv7/a;->b:Landroid/graphics/Bitmap;

    .line 21
    .line 22
    invoke-virtual {p1, p0, v0}, Ljava/util/TreeMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    :cond_0
    invoke-virtual {p1, p0}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    check-cast p0, Lv7/a;

    .line 30
    .line 31
    iget-object p0, p0, Lv7/a;->a:Ljava/lang/CharSequence;

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 34
    .line 35
    .line 36
    check-cast p0, Landroid/text/SpannableStringBuilder;

    .line 37
    .line 38
    return-object p0
.end method


# virtual methods
.method public final b(I)Lr9/c;
    .locals 0

    .line 1
    iget-object p0, p0, Lr9/c;->m:Ljava/util/ArrayList;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lr9/c;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 13
    .line 14
    invoke-direct {p0}, Ljava/lang/IndexOutOfBoundsException;-><init>()V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public final c()I
    .locals 0

    .line 1
    iget-object p0, p0, Lr9/c;->m:Ljava/util/ArrayList;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public final d(Ljava/util/TreeSet;Z)V
    .locals 6

    .line 1
    const-string v0, "p"

    .line 2
    .line 3
    iget-object v1, p0, Lr9/c;->a:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const-string v2, "div"

    .line 10
    .line 11
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-nez p2, :cond_0

    .line 16
    .line 17
    if-nez v0, :cond_0

    .line 18
    .line 19
    if-eqz v1, :cond_2

    .line 20
    .line 21
    iget-object v1, p0, Lr9/c;->i:Ljava/lang/String;

    .line 22
    .line 23
    if-eqz v1, :cond_2

    .line 24
    .line 25
    :cond_0
    iget-wide v1, p0, Lr9/c;->d:J

    .line 26
    .line 27
    const-wide v3, -0x7fffffffffffffffL    # -4.9E-324

    .line 28
    .line 29
    .line 30
    .line 31
    .line 32
    cmp-long v5, v1, v3

    .line 33
    .line 34
    if-eqz v5, :cond_1

    .line 35
    .line 36
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    invoke-virtual {p1, v1}, Ljava/util/TreeSet;->add(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    :cond_1
    iget-wide v1, p0, Lr9/c;->e:J

    .line 44
    .line 45
    cmp-long v3, v1, v3

    .line 46
    .line 47
    if-eqz v3, :cond_2

    .line 48
    .line 49
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    invoke-virtual {p1, v1}, Ljava/util/TreeSet;->add(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    :cond_2
    iget-object v1, p0, Lr9/c;->m:Ljava/util/ArrayList;

    .line 57
    .line 58
    if-nez v1, :cond_3

    .line 59
    .line 60
    goto :goto_3

    .line 61
    :cond_3
    const/4 v1, 0x0

    .line 62
    move v2, v1

    .line 63
    :goto_0
    iget-object v3, p0, Lr9/c;->m:Ljava/util/ArrayList;

    .line 64
    .line 65
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    if-ge v2, v3, :cond_6

    .line 70
    .line 71
    iget-object v3, p0, Lr9/c;->m:Ljava/util/ArrayList;

    .line 72
    .line 73
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v3

    .line 77
    check-cast v3, Lr9/c;

    .line 78
    .line 79
    if-nez p2, :cond_5

    .line 80
    .line 81
    if-eqz v0, :cond_4

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_4
    move v4, v1

    .line 85
    goto :goto_2

    .line 86
    :cond_5
    :goto_1
    const/4 v4, 0x1

    .line 87
    :goto_2
    invoke-virtual {v3, p1, v4}, Lr9/c;->d(Ljava/util/TreeSet;Z)V

    .line 88
    .line 89
    .line 90
    add-int/lit8 v2, v2, 0x1

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_6
    :goto_3
    return-void
.end method

.method public final f(J)Z
    .locals 7

    .line 1
    iget-wide v0, p0, Lr9/c;->d:J

    .line 2
    .line 3
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    cmp-long v4, v0, v2

    .line 9
    .line 10
    iget-wide v5, p0, Lr9/c;->e:J

    .line 11
    .line 12
    if-nez v4, :cond_0

    .line 13
    .line 14
    cmp-long p0, v5, v2

    .line 15
    .line 16
    if-eqz p0, :cond_3

    .line 17
    .line 18
    :cond_0
    cmp-long p0, v0, p1

    .line 19
    .line 20
    if-gtz p0, :cond_1

    .line 21
    .line 22
    cmp-long p0, v5, v2

    .line 23
    .line 24
    if-eqz p0, :cond_3

    .line 25
    .line 26
    :cond_1
    cmp-long p0, v0, v2

    .line 27
    .line 28
    if-nez p0, :cond_2

    .line 29
    .line 30
    cmp-long p0, p1, v5

    .line 31
    .line 32
    if-ltz p0, :cond_3

    .line 33
    .line 34
    :cond_2
    cmp-long p0, v0, p1

    .line 35
    .line 36
    if-gtz p0, :cond_4

    .line 37
    .line 38
    cmp-long p0, p1, v5

    .line 39
    .line 40
    if-gez p0, :cond_4

    .line 41
    .line 42
    :cond_3
    const/4 p0, 0x1

    .line 43
    return p0

    .line 44
    :cond_4
    const/4 p0, 0x0

    .line 45
    return p0
.end method

.method public final g(JLjava/lang/String;Ljava/util/ArrayList;)V
    .locals 2

    .line 1
    const-string v0, ""

    .line 2
    .line 3
    iget-object v1, p0, Lr9/c;->h:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move-object p3, v1

    .line 13
    :goto_0
    invoke-virtual {p0, p1, p2}, Lr9/c;->f(J)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    const-string v0, "div"

    .line 20
    .line 21
    iget-object v1, p0, Lr9/c;->a:Ljava/lang/String;

    .line 22
    .line 23
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_1

    .line 28
    .line 29
    iget-object v0, p0, Lr9/c;->i:Ljava/lang/String;

    .line 30
    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    new-instance p0, Landroid/util/Pair;

    .line 34
    .line 35
    invoke-direct {p0, p3, v0}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p4, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :cond_1
    const/4 v0, 0x0

    .line 43
    :goto_1
    invoke-virtual {p0}, Lr9/c;->c()I

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-ge v0, v1, :cond_2

    .line 48
    .line 49
    invoke-virtual {p0, v0}, Lr9/c;->b(I)Lr9/c;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    invoke-virtual {v1, p1, p2, p3, p4}, Lr9/c;->g(JLjava/lang/String;Ljava/util/ArrayList;)V

    .line 54
    .line 55
    .line 56
    add-int/lit8 v0, v0, 0x1

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_2
    return-void
.end method

.method public final h(JLjava/util/Map;Ljava/util/HashMap;Ljava/lang/String;Ljava/util/TreeMap;)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v4, p3

    .line 4
    .line 5
    invoke-virtual/range {p0 .. p2}, Lr9/c;->f(J)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    goto/16 :goto_1d

    .line 12
    .line 13
    :cond_0
    const-string v1, ""

    .line 14
    .line 15
    iget-object v2, v0, Lr9/c;->h:Ljava/lang/String;

    .line 16
    .line 17
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_1

    .line 22
    .line 23
    move-object/from16 v6, p5

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    move-object v6, v2

    .line 27
    :goto_0
    iget-object v1, v0, Lr9/c;->l:Ljava/util/HashMap;

    .line 28
    .line 29
    invoke-virtual {v1}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-eqz v2, :cond_32

    .line 42
    .line 43
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    check-cast v2, Ljava/util/Map$Entry;

    .line 48
    .line 49
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v5

    .line 53
    check-cast v5, Ljava/lang/String;

    .line 54
    .line 55
    iget-object v7, v0, Lr9/c;->k:Ljava/util/HashMap;

    .line 56
    .line 57
    invoke-virtual {v7, v5}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v8

    .line 61
    if-eqz v8, :cond_2

    .line 62
    .line 63
    invoke-virtual {v7, v5}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v7

    .line 67
    check-cast v7, Ljava/lang/Integer;

    .line 68
    .line 69
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 70
    .line 71
    .line 72
    move-result v7

    .line 73
    goto :goto_2

    .line 74
    :cond_2
    const/4 v7, 0x0

    .line 75
    :goto_2
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    check-cast v2, Ljava/lang/Integer;

    .line 80
    .line 81
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 82
    .line 83
    .line 84
    move-result v2

    .line 85
    if-eq v7, v2, :cond_2f

    .line 86
    .line 87
    move-object/from16 v8, p6

    .line 88
    .line 89
    invoke-virtual {v8, v5}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v5

    .line 93
    check-cast v5, Lv7/a;

    .line 94
    .line 95
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 96
    .line 97
    .line 98
    move-object/from16 v9, p4

    .line 99
    .line 100
    invoke-virtual {v9, v6}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v10

    .line 104
    check-cast v10, Lr9/f;

    .line 105
    .line 106
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 107
    .line 108
    .line 109
    iget v10, v10, Lr9/f;->j:I

    .line 110
    .line 111
    iget-object v11, v0, Lr9/c;->f:Lr9/g;

    .line 112
    .line 113
    iget-object v12, v0, Lr9/c;->g:[Ljava/lang/String;

    .line 114
    .line 115
    invoke-static {v11, v12, v4}, Lkp/s;->e(Lr9/g;[Ljava/lang/String;Ljava/util/Map;)Lr9/g;

    .line 116
    .line 117
    .line 118
    move-result-object v11

    .line 119
    iget-object v12, v5, Lv7/a;->a:Ljava/lang/CharSequence;

    .line 120
    .line 121
    check-cast v12, Landroid/text/SpannableStringBuilder;

    .line 122
    .line 123
    const/4 v13, 0x0

    .line 124
    if-nez v12, :cond_3

    .line 125
    .line 126
    new-instance v12, Landroid/text/SpannableStringBuilder;

    .line 127
    .line 128
    invoke-direct {v12}, Landroid/text/SpannableStringBuilder;-><init>()V

    .line 129
    .line 130
    .line 131
    iput-object v12, v5, Lv7/a;->a:Ljava/lang/CharSequence;

    .line 132
    .line 133
    iput-object v13, v5, Lv7/a;->b:Landroid/graphics/Bitmap;

    .line 134
    .line 135
    :cond_3
    if-eqz v11, :cond_30

    .line 136
    .line 137
    iget v14, v11, Lr9/g;->h:I

    .line 138
    .line 139
    const/4 v15, -0x1

    .line 140
    const/4 v3, 0x1

    .line 141
    if-ne v14, v15, :cond_4

    .line 142
    .line 143
    iget v13, v11, Lr9/g;->i:I

    .line 144
    .line 145
    if-ne v13, v15, :cond_4

    .line 146
    .line 147
    move v13, v15

    .line 148
    goto :goto_5

    .line 149
    :cond_4
    if-ne v14, v3, :cond_5

    .line 150
    .line 151
    move v13, v3

    .line 152
    goto :goto_3

    .line 153
    :cond_5
    const/4 v13, 0x0

    .line 154
    :goto_3
    iget v14, v11, Lr9/g;->i:I

    .line 155
    .line 156
    if-ne v14, v3, :cond_6

    .line 157
    .line 158
    const/4 v14, 0x2

    .line 159
    goto :goto_4

    .line 160
    :cond_6
    const/4 v14, 0x0

    .line 161
    :goto_4
    or-int/2addr v13, v14

    .line 162
    :goto_5
    if-eq v13, v15, :cond_b

    .line 163
    .line 164
    new-instance v13, Landroid/text/style/StyleSpan;

    .line 165
    .line 166
    iget v14, v11, Lr9/g;->h:I

    .line 167
    .line 168
    if-ne v14, v15, :cond_8

    .line 169
    .line 170
    iget v3, v11, Lr9/g;->i:I

    .line 171
    .line 172
    if-ne v3, v15, :cond_7

    .line 173
    .line 174
    move v14, v15

    .line 175
    const/4 v3, 0x1

    .line 176
    goto :goto_8

    .line 177
    :cond_7
    const/4 v3, 0x1

    .line 178
    :cond_8
    if-ne v14, v3, :cond_9

    .line 179
    .line 180
    move/from16 v18, v3

    .line 181
    .line 182
    goto :goto_6

    .line 183
    :cond_9
    const/16 v18, 0x0

    .line 184
    .line 185
    :goto_6
    iget v14, v11, Lr9/g;->i:I

    .line 186
    .line 187
    if-ne v14, v3, :cond_a

    .line 188
    .line 189
    const/4 v14, 0x2

    .line 190
    goto :goto_7

    .line 191
    :cond_a
    const/4 v14, 0x0

    .line 192
    :goto_7
    or-int v14, v18, v14

    .line 193
    .line 194
    :goto_8
    invoke-direct {v13, v14}, Landroid/text/style/StyleSpan;-><init>(I)V

    .line 195
    .line 196
    .line 197
    const/16 v14, 0x21

    .line 198
    .line 199
    invoke-interface {v12, v13, v7, v2, v14}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 200
    .line 201
    .line 202
    goto :goto_9

    .line 203
    :cond_b
    const/16 v14, 0x21

    .line 204
    .line 205
    :goto_9
    iget v13, v11, Lr9/g;->f:I

    .line 206
    .line 207
    if-ne v13, v3, :cond_c

    .line 208
    .line 209
    new-instance v13, Landroid/text/style/StrikethroughSpan;

    .line 210
    .line 211
    invoke-direct {v13}, Landroid/text/style/StrikethroughSpan;-><init>()V

    .line 212
    .line 213
    .line 214
    invoke-interface {v12, v13, v7, v2, v14}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 215
    .line 216
    .line 217
    :cond_c
    iget v13, v11, Lr9/g;->g:I

    .line 218
    .line 219
    if-ne v13, v3, :cond_d

    .line 220
    .line 221
    new-instance v3, Landroid/text/style/UnderlineSpan;

    .line 222
    .line 223
    invoke-direct {v3}, Landroid/text/style/UnderlineSpan;-><init>()V

    .line 224
    .line 225
    .line 226
    invoke-interface {v12, v3, v7, v2, v14}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 227
    .line 228
    .line 229
    :cond_d
    iget-boolean v3, v11, Lr9/g;->c:Z

    .line 230
    .line 231
    if-eqz v3, :cond_f

    .line 232
    .line 233
    new-instance v3, Landroid/text/style/ForegroundColorSpan;

    .line 234
    .line 235
    iget-boolean v13, v11, Lr9/g;->c:Z

    .line 236
    .line 237
    if-eqz v13, :cond_e

    .line 238
    .line 239
    iget v13, v11, Lr9/g;->b:I

    .line 240
    .line 241
    invoke-direct {v3, v13}, Landroid/text/style/ForegroundColorSpan;-><init>(I)V

    .line 242
    .line 243
    .line 244
    invoke-static {v12, v3, v7, v2}, Llp/ab;->a(Landroid/text/SpannableStringBuilder;Ljava/lang/Object;II)V

    .line 245
    .line 246
    .line 247
    goto :goto_a

    .line 248
    :cond_e
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 249
    .line 250
    const-string v1, "Font color has not been defined."

    .line 251
    .line 252
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    throw v0

    .line 256
    :cond_f
    :goto_a
    iget-boolean v3, v11, Lr9/g;->e:Z

    .line 257
    .line 258
    if-eqz v3, :cond_11

    .line 259
    .line 260
    new-instance v3, Landroid/text/style/BackgroundColorSpan;

    .line 261
    .line 262
    iget-boolean v13, v11, Lr9/g;->e:Z

    .line 263
    .line 264
    if-eqz v13, :cond_10

    .line 265
    .line 266
    iget v13, v11, Lr9/g;->d:I

    .line 267
    .line 268
    invoke-direct {v3, v13}, Landroid/text/style/BackgroundColorSpan;-><init>(I)V

    .line 269
    .line 270
    .line 271
    invoke-static {v12, v3, v7, v2}, Llp/ab;->a(Landroid/text/SpannableStringBuilder;Ljava/lang/Object;II)V

    .line 272
    .line 273
    .line 274
    goto :goto_b

    .line 275
    :cond_10
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 276
    .line 277
    const-string v1, "Background color has not been defined."

    .line 278
    .line 279
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 280
    .line 281
    .line 282
    throw v0

    .line 283
    :cond_11
    :goto_b
    iget-object v3, v11, Lr9/g;->a:Ljava/lang/String;

    .line 284
    .line 285
    if-eqz v3, :cond_12

    .line 286
    .line 287
    new-instance v3, Landroid/text/style/TypefaceSpan;

    .line 288
    .line 289
    iget-object v13, v11, Lr9/g;->a:Ljava/lang/String;

    .line 290
    .line 291
    invoke-direct {v3, v13}, Landroid/text/style/TypefaceSpan;-><init>(Ljava/lang/String;)V

    .line 292
    .line 293
    .line 294
    invoke-static {v12, v3, v7, v2}, Llp/ab;->a(Landroid/text/SpannableStringBuilder;Ljava/lang/Object;II)V

    .line 295
    .line 296
    .line 297
    :cond_12
    iget-object v3, v11, Lr9/g;->r:Lr9/b;

    .line 298
    .line 299
    const/4 v13, 0x3

    .line 300
    if-eqz v3, :cond_17

    .line 301
    .line 302
    iget v14, v3, Lr9/b;->a:I

    .line 303
    .line 304
    if-ne v14, v15, :cond_15

    .line 305
    .line 306
    const/4 v15, 0x2

    .line 307
    if-eq v10, v15, :cond_14

    .line 308
    .line 309
    const/4 v14, 0x1

    .line 310
    if-ne v10, v14, :cond_13

    .line 311
    .line 312
    goto :goto_c

    .line 313
    :cond_13
    const/4 v10, 0x1

    .line 314
    goto :goto_d

    .line 315
    :cond_14
    :goto_c
    move v10, v13

    .line 316
    :goto_d
    move v14, v10

    .line 317
    const/4 v10, 0x1

    .line 318
    goto :goto_e

    .line 319
    :cond_15
    iget v10, v3, Lr9/b;->b:I

    .line 320
    .line 321
    :goto_e
    iget v3, v3, Lr9/b;->c:I

    .line 322
    .line 323
    const/4 v15, -0x2

    .line 324
    if-ne v3, v15, :cond_16

    .line 325
    .line 326
    const/4 v3, 0x1

    .line 327
    :cond_16
    new-instance v15, Lv7/h;

    .line 328
    .line 329
    invoke-direct {v15, v14, v10, v3}, Lv7/h;-><init>(III)V

    .line 330
    .line 331
    .line 332
    invoke-static {v12, v15, v7, v2}, Llp/ab;->a(Landroid/text/SpannableStringBuilder;Ljava/lang/Object;II)V

    .line 333
    .line 334
    .line 335
    :cond_17
    iget v3, v11, Lr9/g;->m:I

    .line 336
    .line 337
    const/4 v15, 0x2

    .line 338
    if-eq v3, v15, :cond_19

    .line 339
    .line 340
    if-eq v3, v13, :cond_18

    .line 341
    .line 342
    const/4 v10, 0x4

    .line 343
    if-eq v3, v10, :cond_18

    .line 344
    .line 345
    :goto_f
    const/4 v10, 0x0

    .line 346
    goto/16 :goto_17

    .line 347
    .line 348
    :cond_18
    new-instance v3, Lr9/a;

    .line 349
    .line 350
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 351
    .line 352
    .line 353
    const/16 v14, 0x21

    .line 354
    .line 355
    invoke-interface {v12, v3, v7, v2, v14}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 356
    .line 357
    .line 358
    goto :goto_f

    .line 359
    :cond_19
    iget-object v3, v0, Lr9/c;->j:Lr9/c;

    .line 360
    .line 361
    :goto_10
    if-eqz v3, :cond_1b

    .line 362
    .line 363
    iget-object v10, v3, Lr9/c;->f:Lr9/g;

    .line 364
    .line 365
    iget-object v14, v3, Lr9/c;->g:[Ljava/lang/String;

    .line 366
    .line 367
    invoke-static {v10, v14, v4}, Lkp/s;->e(Lr9/g;[Ljava/lang/String;Ljava/util/Map;)Lr9/g;

    .line 368
    .line 369
    .line 370
    move-result-object v10

    .line 371
    if-eqz v10, :cond_1a

    .line 372
    .line 373
    iget v10, v10, Lr9/g;->m:I

    .line 374
    .line 375
    const/4 v14, 0x1

    .line 376
    if-ne v10, v14, :cond_1a

    .line 377
    .line 378
    goto :goto_11

    .line 379
    :cond_1a
    iget-object v3, v3, Lr9/c;->j:Lr9/c;

    .line 380
    .line 381
    goto :goto_10

    .line 382
    :cond_1b
    const/4 v3, 0x0

    .line 383
    :goto_11
    if-nez v3, :cond_1c

    .line 384
    .line 385
    goto :goto_f

    .line 386
    :cond_1c
    new-instance v10, Ljava/util/ArrayDeque;

    .line 387
    .line 388
    invoke-direct {v10}, Ljava/util/ArrayDeque;-><init>()V

    .line 389
    .line 390
    .line 391
    invoke-virtual {v10, v3}, Ljava/util/ArrayDeque;->push(Ljava/lang/Object;)V

    .line 392
    .line 393
    .line 394
    :goto_12
    invoke-virtual {v10}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 395
    .line 396
    .line 397
    move-result v14

    .line 398
    if-nez v14, :cond_1f

    .line 399
    .line 400
    invoke-virtual {v10}, Ljava/util/ArrayDeque;->pop()Ljava/lang/Object;

    .line 401
    .line 402
    .line 403
    move-result-object v14

    .line 404
    check-cast v14, Lr9/c;

    .line 405
    .line 406
    iget-object v15, v14, Lr9/c;->f:Lr9/g;

    .line 407
    .line 408
    iget-object v13, v14, Lr9/c;->g:[Ljava/lang/String;

    .line 409
    .line 410
    invoke-static {v15, v13, v4}, Lkp/s;->e(Lr9/g;[Ljava/lang/String;Ljava/util/Map;)Lr9/g;

    .line 411
    .line 412
    .line 413
    move-result-object v13

    .line 414
    if-eqz v13, :cond_1d

    .line 415
    .line 416
    iget v13, v13, Lr9/g;->m:I

    .line 417
    .line 418
    const/4 v15, 0x3

    .line 419
    if-ne v13, v15, :cond_1d

    .line 420
    .line 421
    move-object v13, v14

    .line 422
    goto :goto_14

    .line 423
    :cond_1d
    invoke-virtual {v14}, Lr9/c;->c()I

    .line 424
    .line 425
    .line 426
    move-result v13

    .line 427
    const/16 v18, 0x1

    .line 428
    .line 429
    add-int/lit8 v13, v13, -0x1

    .line 430
    .line 431
    :goto_13
    if-ltz v13, :cond_1e

    .line 432
    .line 433
    invoke-virtual {v14, v13}, Lr9/c;->b(I)Lr9/c;

    .line 434
    .line 435
    .line 436
    move-result-object v15

    .line 437
    invoke-virtual {v10, v15}, Ljava/util/ArrayDeque;->push(Ljava/lang/Object;)V

    .line 438
    .line 439
    .line 440
    add-int/lit8 v13, v13, -0x1

    .line 441
    .line 442
    goto :goto_13

    .line 443
    :cond_1e
    const/4 v13, 0x3

    .line 444
    goto :goto_12

    .line 445
    :cond_1f
    const/4 v13, 0x0

    .line 446
    :goto_14
    if-nez v13, :cond_20

    .line 447
    .line 448
    goto :goto_f

    .line 449
    :cond_20
    invoke-virtual {v13}, Lr9/c;->c()I

    .line 450
    .line 451
    .line 452
    move-result v10

    .line 453
    const/4 v14, 0x1

    .line 454
    if-ne v10, v14, :cond_23

    .line 455
    .line 456
    const/4 v10, 0x0

    .line 457
    invoke-virtual {v13, v10}, Lr9/c;->b(I)Lr9/c;

    .line 458
    .line 459
    .line 460
    move-result-object v14

    .line 461
    iget-object v14, v14, Lr9/c;->b:Ljava/lang/String;

    .line 462
    .line 463
    if-eqz v14, :cond_24

    .line 464
    .line 465
    invoke-virtual {v13, v10}, Lr9/c;->b(I)Lr9/c;

    .line 466
    .line 467
    .line 468
    move-result-object v14

    .line 469
    iget-object v14, v14, Lr9/c;->b:Ljava/lang/String;

    .line 470
    .line 471
    sget-object v15, Lw7/w;->a:Ljava/lang/String;

    .line 472
    .line 473
    iget-object v15, v13, Lr9/c;->f:Lr9/g;

    .line 474
    .line 475
    iget-object v13, v13, Lr9/c;->g:[Ljava/lang/String;

    .line 476
    .line 477
    invoke-static {v15, v13, v4}, Lkp/s;->e(Lr9/g;[Ljava/lang/String;Ljava/util/Map;)Lr9/g;

    .line 478
    .line 479
    .line 480
    move-result-object v13

    .line 481
    if-eqz v13, :cond_21

    .line 482
    .line 483
    iget v13, v13, Lr9/g;->n:I

    .line 484
    .line 485
    :goto_15
    const/4 v15, -0x1

    .line 486
    goto :goto_16

    .line 487
    :cond_21
    const/4 v13, -0x1

    .line 488
    goto :goto_15

    .line 489
    :goto_16
    if-ne v13, v15, :cond_22

    .line 490
    .line 491
    iget-object v15, v3, Lr9/c;->f:Lr9/g;

    .line 492
    .line 493
    iget-object v3, v3, Lr9/c;->g:[Ljava/lang/String;

    .line 494
    .line 495
    invoke-static {v15, v3, v4}, Lkp/s;->e(Lr9/g;[Ljava/lang/String;Ljava/util/Map;)Lr9/g;

    .line 496
    .line 497
    .line 498
    move-result-object v3

    .line 499
    if-eqz v3, :cond_22

    .line 500
    .line 501
    iget v13, v3, Lr9/g;->n:I

    .line 502
    .line 503
    :cond_22
    new-instance v3, Lv7/g;

    .line 504
    .line 505
    invoke-direct {v3, v14, v13}, Lv7/g;-><init>(Ljava/lang/String;I)V

    .line 506
    .line 507
    .line 508
    const/16 v14, 0x21

    .line 509
    .line 510
    invoke-interface {v12, v3, v7, v2, v14}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 511
    .line 512
    .line 513
    goto :goto_17

    .line 514
    :cond_23
    const/4 v10, 0x0

    .line 515
    :cond_24
    const-string v3, "TtmlRenderUtil"

    .line 516
    .line 517
    const-string v13, "Skipping rubyText node without exactly one text child."

    .line 518
    .line 519
    invoke-static {v3, v13}, Lw7/a;->s(Ljava/lang/String;Ljava/lang/String;)V

    .line 520
    .line 521
    .line 522
    :goto_17
    iget v3, v11, Lr9/g;->q:I

    .line 523
    .line 524
    const/4 v14, 0x1

    .line 525
    if-ne v3, v14, :cond_25

    .line 526
    .line 527
    new-instance v3, Lv7/e;

    .line 528
    .line 529
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 530
    .line 531
    .line 532
    invoke-static {v12, v3, v7, v2}, Llp/ab;->a(Landroid/text/SpannableStringBuilder;Ljava/lang/Object;II)V

    .line 533
    .line 534
    .line 535
    :cond_25
    iget v3, v11, Lr9/g;->j:I

    .line 536
    .line 537
    const/high16 v13, 0x42c80000    # 100.0f

    .line 538
    .line 539
    if-eq v3, v14, :cond_2c

    .line 540
    .line 541
    const/4 v15, 0x2

    .line 542
    if-eq v3, v15, :cond_2b

    .line 543
    .line 544
    const/4 v15, 0x3

    .line 545
    if-eq v3, v15, :cond_26

    .line 546
    .line 547
    move-object/from16 v16, v1

    .line 548
    .line 549
    move/from16 p5, v13

    .line 550
    .line 551
    goto/16 :goto_1a

    .line 552
    .line 553
    :cond_26
    iget v3, v11, Lr9/g;->k:F

    .line 554
    .line 555
    div-float/2addr v3, v13

    .line 556
    const-class v14, Landroid/text/style/RelativeSizeSpan;

    .line 557
    .line 558
    invoke-interface {v12, v7, v2, v14}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 559
    .line 560
    .line 561
    move-result-object v14

    .line 562
    check-cast v14, [Landroid/text/style/RelativeSizeSpan;

    .line 563
    .line 564
    array-length v15, v14

    .line 565
    move/from16 v19, v10

    .line 566
    .line 567
    move v10, v3

    .line 568
    move/from16 v3, v19

    .line 569
    .line 570
    :goto_18
    if-ge v3, v15, :cond_2a

    .line 571
    .line 572
    move/from16 p5, v13

    .line 573
    .line 574
    aget-object v13, v14, v3

    .line 575
    .line 576
    move-object/from16 v16, v1

    .line 577
    .line 578
    invoke-interface {v12, v13}, Landroid/text/Spanned;->getSpanStart(Ljava/lang/Object;)I

    .line 579
    .line 580
    .line 581
    move-result v1

    .line 582
    if-gt v1, v7, :cond_27

    .line 583
    .line 584
    invoke-interface {v12, v13}, Landroid/text/Spanned;->getSpanEnd(Ljava/lang/Object;)I

    .line 585
    .line 586
    .line 587
    move-result v1

    .line 588
    if-lt v1, v2, :cond_27

    .line 589
    .line 590
    invoke-virtual {v13}, Landroid/text/style/RelativeSizeSpan;->getSizeChange()F

    .line 591
    .line 592
    .line 593
    move-result v1

    .line 594
    mul-float/2addr v1, v10

    .line 595
    move v10, v1

    .line 596
    :cond_27
    invoke-interface {v12, v13}, Landroid/text/Spanned;->getSpanStart(Ljava/lang/Object;)I

    .line 597
    .line 598
    .line 599
    move-result v1

    .line 600
    if-ne v1, v7, :cond_28

    .line 601
    .line 602
    invoke-interface {v12, v13}, Landroid/text/Spanned;->getSpanEnd(Ljava/lang/Object;)I

    .line 603
    .line 604
    .line 605
    move-result v1

    .line 606
    if-ne v1, v2, :cond_28

    .line 607
    .line 608
    invoke-interface {v12, v13}, Landroid/text/Spanned;->getSpanFlags(Ljava/lang/Object;)I

    .line 609
    .line 610
    .line 611
    move-result v1

    .line 612
    move/from16 v17, v3

    .line 613
    .line 614
    const/16 v3, 0x21

    .line 615
    .line 616
    if-ne v1, v3, :cond_29

    .line 617
    .line 618
    invoke-interface {v12, v13}, Landroid/text/Spannable;->removeSpan(Ljava/lang/Object;)V

    .line 619
    .line 620
    .line 621
    goto :goto_19

    .line 622
    :cond_28
    move/from16 v17, v3

    .line 623
    .line 624
    :cond_29
    :goto_19
    add-int/lit8 v3, v17, 0x1

    .line 625
    .line 626
    move/from16 v13, p5

    .line 627
    .line 628
    move-object/from16 v1, v16

    .line 629
    .line 630
    goto :goto_18

    .line 631
    :cond_2a
    move-object/from16 v16, v1

    .line 632
    .line 633
    move/from16 p5, v13

    .line 634
    .line 635
    new-instance v1, Landroid/text/style/RelativeSizeSpan;

    .line 636
    .line 637
    invoke-direct {v1, v10}, Landroid/text/style/RelativeSizeSpan;-><init>(F)V

    .line 638
    .line 639
    .line 640
    const/16 v14, 0x21

    .line 641
    .line 642
    invoke-interface {v12, v1, v7, v2, v14}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 643
    .line 644
    .line 645
    goto :goto_1a

    .line 646
    :cond_2b
    move-object/from16 v16, v1

    .line 647
    .line 648
    move/from16 p5, v13

    .line 649
    .line 650
    new-instance v1, Landroid/text/style/RelativeSizeSpan;

    .line 651
    .line 652
    iget v3, v11, Lr9/g;->k:F

    .line 653
    .line 654
    invoke-direct {v1, v3}, Landroid/text/style/RelativeSizeSpan;-><init>(F)V

    .line 655
    .line 656
    .line 657
    invoke-static {v12, v1, v7, v2}, Llp/ab;->a(Landroid/text/SpannableStringBuilder;Ljava/lang/Object;II)V

    .line 658
    .line 659
    .line 660
    goto :goto_1a

    .line 661
    :cond_2c
    move-object/from16 v16, v1

    .line 662
    .line 663
    move/from16 p5, v13

    .line 664
    .line 665
    new-instance v1, Landroid/text/style/AbsoluteSizeSpan;

    .line 666
    .line 667
    iget v3, v11, Lr9/g;->k:F

    .line 668
    .line 669
    float-to-int v3, v3

    .line 670
    const/4 v14, 0x1

    .line 671
    invoke-direct {v1, v3, v14}, Landroid/text/style/AbsoluteSizeSpan;-><init>(IZ)V

    .line 672
    .line 673
    .line 674
    invoke-static {v12, v1, v7, v2}, Llp/ab;->a(Landroid/text/SpannableStringBuilder;Ljava/lang/Object;II)V

    .line 675
    .line 676
    .line 677
    :goto_1a
    const-string v1, "p"

    .line 678
    .line 679
    iget-object v2, v0, Lr9/c;->a:Ljava/lang/String;

    .line 680
    .line 681
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 682
    .line 683
    .line 684
    move-result v1

    .line 685
    if-eqz v1, :cond_31

    .line 686
    .line 687
    iget v1, v11, Lr9/g;->s:F

    .line 688
    .line 689
    const v2, 0x7f7fffff    # Float.MAX_VALUE

    .line 690
    .line 691
    .line 692
    cmpl-float v2, v1, v2

    .line 693
    .line 694
    if-eqz v2, :cond_2d

    .line 695
    .line 696
    const/high16 v2, -0x3d4c0000    # -90.0f

    .line 697
    .line 698
    mul-float/2addr v1, v2

    .line 699
    div-float v1, v1, p5

    .line 700
    .line 701
    iput v1, v5, Lv7/a;->q:F

    .line 702
    .line 703
    :cond_2d
    iget-object v1, v11, Lr9/g;->o:Landroid/text/Layout$Alignment;

    .line 704
    .line 705
    if-eqz v1, :cond_2e

    .line 706
    .line 707
    iput-object v1, v5, Lv7/a;->c:Landroid/text/Layout$Alignment;

    .line 708
    .line 709
    :cond_2e
    iget-object v1, v11, Lr9/g;->p:Landroid/text/Layout$Alignment;

    .line 710
    .line 711
    if-eqz v1, :cond_31

    .line 712
    .line 713
    iput-object v1, v5, Lv7/a;->d:Landroid/text/Layout$Alignment;

    .line 714
    .line 715
    goto :goto_1b

    .line 716
    :cond_2f
    move-object/from16 v9, p4

    .line 717
    .line 718
    move-object/from16 v8, p6

    .line 719
    .line 720
    :cond_30
    move-object/from16 v16, v1

    .line 721
    .line 722
    :cond_31
    :goto_1b
    move-object/from16 v1, v16

    .line 723
    .line 724
    goto/16 :goto_1

    .line 725
    .line 726
    :cond_32
    const/4 v10, 0x0

    .line 727
    :goto_1c
    move-object/from16 v9, p4

    .line 728
    .line 729
    move-object/from16 v8, p6

    .line 730
    .line 731
    invoke-virtual {v0}, Lr9/c;->c()I

    .line 732
    .line 733
    .line 734
    move-result v1

    .line 735
    if-ge v10, v1, :cond_33

    .line 736
    .line 737
    invoke-virtual {v0, v10}, Lr9/c;->b(I)Lr9/c;

    .line 738
    .line 739
    .line 740
    move-result-object v1

    .line 741
    move-wide/from16 v2, p1

    .line 742
    .line 743
    move-object v7, v8

    .line 744
    move-object v5, v9

    .line 745
    invoke-virtual/range {v1 .. v7}, Lr9/c;->h(JLjava/util/Map;Ljava/util/HashMap;Ljava/lang/String;Ljava/util/TreeMap;)V

    .line 746
    .line 747
    .line 748
    add-int/lit8 v10, v10, 0x1

    .line 749
    .line 750
    move-object/from16 v4, p3

    .line 751
    .line 752
    goto :goto_1c

    .line 753
    :cond_33
    :goto_1d
    return-void
.end method

.method public final i(JZLjava/lang/String;Ljava/util/TreeMap;)V
    .locals 11

    .line 1
    move-object/from16 v5, p5

    .line 2
    .line 3
    iget-object v0, p0, Lr9/c;->k:Ljava/util/HashMap;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/HashMap;->clear()V

    .line 6
    .line 7
    .line 8
    iget-object v6, p0, Lr9/c;->l:Ljava/util/HashMap;

    .line 9
    .line 10
    invoke-virtual {v6}, Ljava/util/HashMap;->clear()V

    .line 11
    .line 12
    .line 13
    const-string v1, "metadata"

    .line 14
    .line 15
    iget-object v2, p0, Lr9/c;->a:Ljava/lang/String;

    .line 16
    .line 17
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    goto/16 :goto_8

    .line 24
    .line 25
    :cond_0
    const-string v1, ""

    .line 26
    .line 27
    iget-object v3, p0, Lr9/c;->h:Ljava/lang/String;

    .line 28
    .line 29
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_1

    .line 34
    .line 35
    move-object v4, p4

    .line 36
    goto :goto_0

    .line 37
    :cond_1
    move-object v4, v3

    .line 38
    :goto_0
    iget-boolean v1, p0, Lr9/c;->c:Z

    .line 39
    .line 40
    if-eqz v1, :cond_2

    .line 41
    .line 42
    if-eqz p3, :cond_2

    .line 43
    .line 44
    invoke-static {v4, v5}, Lr9/c;->e(Ljava/lang/String;Ljava/util/TreeMap;)Landroid/text/SpannableStringBuilder;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    iget-object p0, p0, Lr9/c;->b:Ljava/lang/String;

    .line 49
    .line 50
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 51
    .line 52
    .line 53
    invoke-virtual {p1, p0}, Landroid/text/SpannableStringBuilder;->append(Ljava/lang/CharSequence;)Landroid/text/SpannableStringBuilder;

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :cond_2
    const-string v1, "br"

    .line 58
    .line 59
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    const/16 v7, 0xa

    .line 64
    .line 65
    if-eqz v1, :cond_3

    .line 66
    .line 67
    if-eqz p3, :cond_3

    .line 68
    .line 69
    invoke-static {v4, v5}, Lr9/c;->e(Ljava/lang/String;Ljava/util/TreeMap;)Landroid/text/SpannableStringBuilder;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    invoke-virtual {p0, v7}, Landroid/text/SpannableStringBuilder;->append(C)Landroid/text/SpannableStringBuilder;

    .line 74
    .line 75
    .line 76
    return-void

    .line 77
    :cond_3
    invoke-virtual/range {p0 .. p2}, Lr9/c;->f(J)Z

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    if-eqz v1, :cond_a

    .line 82
    .line 83
    invoke-virtual {v5}, Ljava/util/TreeMap;->entrySet()Ljava/util/Set;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 92
    .line 93
    .line 94
    move-result v3

    .line 95
    if-eqz v3, :cond_4

    .line 96
    .line 97
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v3

    .line 101
    check-cast v3, Ljava/util/Map$Entry;

    .line 102
    .line 103
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v8

    .line 107
    check-cast v8, Ljava/lang/String;

    .line 108
    .line 109
    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v3

    .line 113
    check-cast v3, Lv7/a;

    .line 114
    .line 115
    iget-object v3, v3, Lv7/a;->a:Ljava/lang/CharSequence;

    .line 116
    .line 117
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 118
    .line 119
    .line 120
    check-cast v3, Ljava/lang/CharSequence;

    .line 121
    .line 122
    invoke-interface {v3}, Ljava/lang/CharSequence;->length()I

    .line 123
    .line 124
    .line 125
    move-result v3

    .line 126
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 127
    .line 128
    .line 129
    move-result-object v3

    .line 130
    invoke-virtual {v0, v8, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    goto :goto_1

    .line 134
    :cond_4
    const-string v0, "p"

    .line 135
    .line 136
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v8

    .line 140
    const/4 v9, 0x0

    .line 141
    move v10, v9

    .line 142
    :goto_2
    invoke-virtual {p0}, Lr9/c;->c()I

    .line 143
    .line 144
    .line 145
    move-result v0

    .line 146
    const/4 v1, 0x1

    .line 147
    if-ge v10, v0, :cond_7

    .line 148
    .line 149
    invoke-virtual {p0, v10}, Lr9/c;->b(I)Lr9/c;

    .line 150
    .line 151
    .line 152
    move-result-object v0

    .line 153
    if-nez p3, :cond_6

    .line 154
    .line 155
    if-eqz v8, :cond_5

    .line 156
    .line 157
    goto :goto_4

    .line 158
    :cond_5
    move v3, v9

    .line 159
    :goto_3
    move-wide v1, p1

    .line 160
    goto :goto_5

    .line 161
    :cond_6
    :goto_4
    move v3, v1

    .line 162
    goto :goto_3

    .line 163
    :goto_5
    invoke-virtual/range {v0 .. v5}, Lr9/c;->i(JZLjava/lang/String;Ljava/util/TreeMap;)V

    .line 164
    .line 165
    .line 166
    add-int/lit8 v10, v10, 0x1

    .line 167
    .line 168
    goto :goto_2

    .line 169
    :cond_7
    if-eqz v8, :cond_9

    .line 170
    .line 171
    invoke-static {v4, v5}, Lr9/c;->e(Ljava/lang/String;Ljava/util/TreeMap;)Landroid/text/SpannableStringBuilder;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    invoke-virtual {p0}, Landroid/text/SpannableStringBuilder;->length()I

    .line 176
    .line 177
    .line 178
    move-result p1

    .line 179
    sub-int/2addr p1, v1

    .line 180
    :goto_6
    if-ltz p1, :cond_8

    .line 181
    .line 182
    invoke-virtual {p0, p1}, Landroid/text/SpannableStringBuilder;->charAt(I)C

    .line 183
    .line 184
    .line 185
    move-result p2

    .line 186
    const/16 p3, 0x20

    .line 187
    .line 188
    if-ne p2, p3, :cond_8

    .line 189
    .line 190
    add-int/lit8 p1, p1, -0x1

    .line 191
    .line 192
    goto :goto_6

    .line 193
    :cond_8
    if-ltz p1, :cond_9

    .line 194
    .line 195
    invoke-virtual {p0, p1}, Landroid/text/SpannableStringBuilder;->charAt(I)C

    .line 196
    .line 197
    .line 198
    move-result p1

    .line 199
    if-eq p1, v7, :cond_9

    .line 200
    .line 201
    invoke-virtual {p0, v7}, Landroid/text/SpannableStringBuilder;->append(C)Landroid/text/SpannableStringBuilder;

    .line 202
    .line 203
    .line 204
    :cond_9
    invoke-virtual {v5}, Ljava/util/TreeMap;->entrySet()Ljava/util/Set;

    .line 205
    .line 206
    .line 207
    move-result-object p0

    .line 208
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 209
    .line 210
    .line 211
    move-result-object p0

    .line 212
    :goto_7
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 213
    .line 214
    .line 215
    move-result p1

    .line 216
    if-eqz p1, :cond_a

    .line 217
    .line 218
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object p1

    .line 222
    check-cast p1, Ljava/util/Map$Entry;

    .line 223
    .line 224
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object p2

    .line 228
    check-cast p2, Ljava/lang/String;

    .line 229
    .line 230
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object p1

    .line 234
    check-cast p1, Lv7/a;

    .line 235
    .line 236
    iget-object p1, p1, Lv7/a;->a:Ljava/lang/CharSequence;

    .line 237
    .line 238
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 239
    .line 240
    .line 241
    check-cast p1, Ljava/lang/CharSequence;

    .line 242
    .line 243
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 244
    .line 245
    .line 246
    move-result p1

    .line 247
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 248
    .line 249
    .line 250
    move-result-object p1

    .line 251
    invoke-virtual {v6, p2, p1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    goto :goto_7

    .line 255
    :cond_a
    :goto_8
    return-void
.end method
