.class public final Lf01/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:[J

.field public final c:Ljava/util/ArrayList;

.field public final d:Ljava/util/ArrayList;

.field public e:Z

.field public f:Z

.field public g:La8/b;

.field public h:I

.field public i:J

.field public final synthetic j:Lf01/g;


# direct methods
.method public constructor <init>(Lf01/g;Ljava/lang/String;)V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "key"

    .line 5
    .line 6
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lf01/c;->j:Lf01/g;

    .line 10
    .line 11
    iput-object p2, p0, Lf01/c;->a:Ljava/lang/String;

    .line 12
    .line 13
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    const/4 p1, 0x2

    .line 17
    new-array v0, p1, [J

    .line 18
    .line 19
    iput-object v0, p0, Lf01/c;->b:[J

    .line 20
    .line 21
    new-instance v0, Ljava/util/ArrayList;

    .line 22
    .line 23
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-object v0, p0, Lf01/c;->c:Ljava/util/ArrayList;

    .line 27
    .line 28
    new-instance v0, Ljava/util/ArrayList;

    .line 29
    .line 30
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 31
    .line 32
    .line 33
    iput-object v0, p0, Lf01/c;->d:Ljava/util/ArrayList;

    .line 34
    .line 35
    new-instance v0, Ljava/lang/StringBuilder;

    .line 36
    .line 37
    invoke-direct {v0, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    const/16 p2, 0x2e

    .line 41
    .line 42
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->length()I

    .line 46
    .line 47
    .line 48
    move-result p2

    .line 49
    const/4 v1, 0x0

    .line 50
    :goto_0
    if-ge v1, p1, :cond_0

    .line 51
    .line 52
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    iget-object v2, p0, Lf01/c;->c:Ljava/util/ArrayList;

    .line 56
    .line 57
    iget-object v3, p0, Lf01/c;->j:Lf01/g;

    .line 58
    .line 59
    iget-object v3, v3, Lf01/g;->d:Lu01/y;

    .line 60
    .line 61
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v4

    .line 65
    const-string v5, "toString(...)"

    .line 66
    .line 67
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {v3, v4}, Lu01/y;->e(Ljava/lang/String;)Lu01/y;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    invoke-interface {v2, v3}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    const-string v2, ".tmp"

    .line 78
    .line 79
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    iget-object v2, p0, Lf01/c;->d:Ljava/util/ArrayList;

    .line 83
    .line 84
    iget-object v3, p0, Lf01/c;->j:Lf01/g;

    .line 85
    .line 86
    iget-object v3, v3, Lf01/g;->d:Lu01/y;

    .line 87
    .line 88
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v4

    .line 92
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v3, v4}, Lu01/y;->e(Ljava/lang/String;)Lu01/y;

    .line 96
    .line 97
    .line 98
    move-result-object v3

    .line 99
    invoke-interface {v2, v3}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->setLength(I)V

    .line 103
    .line 104
    .line 105
    add-int/lit8 v1, v1, 0x1

    .line 106
    .line 107
    goto :goto_0

    .line 108
    :cond_0
    return-void
.end method


# virtual methods
.method public final a()Lf01/d;
    .locals 9

    .line 1
    sget-object v0, Le01/g;->a:Ljava/util/TimeZone;

    .line 2
    .line 3
    iget-boolean v0, p0, Lf01/c;->e:Z

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto :goto_3

    .line 8
    :cond_0
    iget-object v0, p0, Lf01/c;->j:Lf01/g;

    .line 9
    .line 10
    iget-boolean v1, v0, Lf01/g;->o:Z

    .line 11
    .line 12
    if-nez v1, :cond_1

    .line 13
    .line 14
    iget-object v1, p0, Lf01/c;->g:La8/b;

    .line 15
    .line 16
    if-nez v1, :cond_5

    .line 17
    .line 18
    iget-boolean v1, p0, Lf01/c;->f:Z

    .line 19
    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    goto :goto_3

    .line 23
    :cond_1
    new-instance v7, Ljava/util/ArrayList;

    .line 24
    .line 25
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lf01/c;->b:[J

    .line 29
    .line 30
    invoke-virtual {v1}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    move-object v8, v1

    .line 35
    check-cast v8, [J

    .line 36
    .line 37
    const/4 v1, 0x0

    .line 38
    :goto_0
    const/4 v2, 0x2

    .line 39
    if-ge v1, v2, :cond_3

    .line 40
    .line 41
    :try_start_0
    iget-object v2, v0, Lf01/g;->e:Lf01/f;

    .line 42
    .line 43
    iget-object v3, p0, Lf01/c;->c:Ljava/util/ArrayList;

    .line 44
    .line 45
    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    check-cast v3, Lu01/y;

    .line 50
    .line 51
    invoke-virtual {v2, v3}, Lu01/l;->H(Lu01/y;)Lu01/h0;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    iget-boolean v3, v0, Lf01/g;->o:Z

    .line 56
    .line 57
    if-eqz v3, :cond_2

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_2
    iget v3, p0, Lf01/c;->h:I

    .line 61
    .line 62
    add-int/lit8 v3, v3, 0x1

    .line 63
    .line 64
    iput v3, p0, Lf01/c;->h:I

    .line 65
    .line 66
    new-instance v3, Lf01/b;

    .line 67
    .line 68
    invoke-direct {v3, v2, v0, p0}, Lf01/b;-><init>(Lu01/h0;Lf01/g;Lf01/c;)V

    .line 69
    .line 70
    .line 71
    move-object v2, v3

    .line 72
    :goto_1
    invoke-virtual {v7, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    add-int/lit8 v1, v1, 0x1

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_3
    new-instance v2, Lf01/d;

    .line 79
    .line 80
    iget-object v3, p0, Lf01/c;->j:Lf01/g;

    .line 81
    .line 82
    iget-object v4, p0, Lf01/c;->a:Ljava/lang/String;

    .line 83
    .line 84
    iget-wide v5, p0, Lf01/c;->i:J

    .line 85
    .line 86
    invoke-direct/range {v2 .. v8}, Lf01/d;-><init>(Lf01/g;Ljava/lang/String;JLjava/util/ArrayList;[J)V
    :try_end_0
    .catch Ljava/io/FileNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 87
    .line 88
    .line 89
    return-object v2

    .line 90
    :catch_0
    invoke-virtual {v7}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    if-eqz v2, :cond_4

    .line 99
    .line 100
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v2

    .line 104
    check-cast v2, Lu01/h0;

    .line 105
    .line 106
    invoke-static {v2}, Le01/e;->b(Ljava/io/Closeable;)V

    .line 107
    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_4
    :try_start_1
    invoke-virtual {v0, p0}, Lf01/g;->B(Lf01/c;)V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1

    .line 111
    .line 112
    .line 113
    :catch_1
    :cond_5
    :goto_3
    const/4 p0, 0x0

    .line 114
    return-object p0
.end method
