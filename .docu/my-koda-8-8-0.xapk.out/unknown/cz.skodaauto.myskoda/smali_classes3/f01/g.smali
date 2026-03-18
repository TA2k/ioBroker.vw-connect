.class public final Lf01/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;
.implements Ljava/io/Flushable;


# static fields
.field public static final A:Ljava/lang/String;

.field public static final w:Lly0/n;

.field public static final x:Ljava/lang/String;

.field public static final y:Ljava/lang/String;

.field public static final z:Ljava/lang/String;


# instance fields
.field public final d:Lu01/y;

.field public final e:Lf01/f;

.field public final f:J

.field public final g:Lu01/y;

.field public final h:Lu01/y;

.field public final i:Lu01/y;

.field public j:J

.field public k:Lu01/a0;

.field public final l:Ljava/util/LinkedHashMap;

.field public m:I

.field public n:Z

.field public o:Z

.field public p:Z

.field public q:Z

.field public r:Z

.field public s:Z

.field public t:J

.field public final u:Lg01/b;

.field public final v:Lf01/e;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lly0/n;

    .line 2
    .line 3
    const-string v1, "[a-z0-9_-]{1,120}"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lly0/n;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lf01/g;->w:Lly0/n;

    .line 9
    .line 10
    const-string v0, "CLEAN"

    .line 11
    .line 12
    sput-object v0, Lf01/g;->x:Ljava/lang/String;

    .line 13
    .line 14
    const-string v0, "DIRTY"

    .line 15
    .line 16
    sput-object v0, Lf01/g;->y:Ljava/lang/String;

    .line 17
    .line 18
    const-string v0, "REMOVE"

    .line 19
    .line 20
    sput-object v0, Lf01/g;->z:Ljava/lang/String;

    .line 21
    .line 22
    const-string v0, "READ"

    .line 23
    .line 24
    sput-object v0, Lf01/g;->A:Ljava/lang/String;

    .line 25
    .line 26
    return-void
.end method

.method public constructor <init>(Lu01/k;Lu01/y;Lg01/c;)V
    .locals 3

    .line 1
    const-string v0, "fileSystem"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "taskRunner"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p2, p0, Lf01/g;->d:Lu01/y;

    .line 15
    .line 16
    new-instance v0, Lf01/f;

    .line 17
    .line 18
    invoke-direct {v0, p1}, Lu01/l;-><init>(Lu01/k;)V

    .line 19
    .line 20
    .line 21
    iput-object v0, p0, Lf01/g;->e:Lf01/f;

    .line 22
    .line 23
    const-wide/32 v0, 0x1400000

    .line 24
    .line 25
    .line 26
    iput-wide v0, p0, Lf01/g;->f:J

    .line 27
    .line 28
    new-instance p1, Ljava/util/LinkedHashMap;

    .line 29
    .line 30
    const/high16 v0, 0x3f400000    # 0.75f

    .line 31
    .line 32
    const/4 v1, 0x1

    .line 33
    const/4 v2, 0x0

    .line 34
    invoke-direct {p1, v2, v0, v1}, Ljava/util/LinkedHashMap;-><init>(IFZ)V

    .line 35
    .line 36
    .line 37
    iput-object p1, p0, Lf01/g;->l:Ljava/util/LinkedHashMap;

    .line 38
    .line 39
    invoke-virtual {p3}, Lg01/c;->d()Lg01/b;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    iput-object p1, p0, Lf01/g;->u:Lg01/b;

    .line 44
    .line 45
    new-instance p1, Ljava/lang/StringBuilder;

    .line 46
    .line 47
    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    .line 48
    .line 49
    .line 50
    sget-object p3, Le01/g;->b:Ljava/lang/String;

    .line 51
    .line 52
    const-string v0, " Cache"

    .line 53
    .line 54
    invoke-static {p1, p3, v0}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    new-instance p3, Lf01/e;

    .line 59
    .line 60
    const/4 v0, 0x0

    .line 61
    invoke-direct {p3, p1, v0, p0}, Lf01/e;-><init>(Ljava/lang/String;ILjava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    iput-object p3, p0, Lf01/g;->v:Lf01/e;

    .line 65
    .line 66
    const-string p1, "journal"

    .line 67
    .line 68
    invoke-virtual {p2, p1}, Lu01/y;->e(Ljava/lang/String;)Lu01/y;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    iput-object p1, p0, Lf01/g;->g:Lu01/y;

    .line 73
    .line 74
    const-string p1, "journal.tmp"

    .line 75
    .line 76
    invoke-virtual {p2, p1}, Lu01/y;->e(Ljava/lang/String;)Lu01/y;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    iput-object p1, p0, Lf01/g;->h:Lu01/y;

    .line 81
    .line 82
    const-string p1, "journal.bkp"

    .line 83
    .line 84
    invoke-virtual {p2, p1}, Lu01/y;->e(Ljava/lang/String;)Lu01/y;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    iput-object p1, p0, Lf01/g;->i:Lu01/y;

    .line 89
    .line 90
    return-void
.end method

.method public static H(Ljava/lang/String;)V
    .locals 2

    .line 1
    sget-object v0, Lf01/g;->w:Lly0/n;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lly0/n;->d(Ljava/lang/CharSequence;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    const-string v0, "keys must match regex [a-z0-9_-]{1,120}: \""

    .line 11
    .line 12
    const/16 v1, 0x22

    .line 13
    .line 14
    invoke-static {v1, v0, p0}, Lvj/b;->f(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw v0
.end method


# virtual methods
.method public final B(Lf01/c;)V
    .locals 10

    .line 1
    iget-object v0, p1, Lf01/c;->a:Ljava/lang/String;

    .line 2
    .line 3
    iget-boolean v1, p0, Lf01/g;->o:Z

    .line 4
    .line 5
    const/16 v2, 0xa

    .line 6
    .line 7
    const/16 v3, 0x20

    .line 8
    .line 9
    const/4 v4, 0x1

    .line 10
    if-nez v1, :cond_2

    .line 11
    .line 12
    iget v1, p1, Lf01/c;->h:I

    .line 13
    .line 14
    if-lez v1, :cond_0

    .line 15
    .line 16
    iget-object v1, p0, Lf01/g;->k:Lu01/a0;

    .line 17
    .line 18
    if-eqz v1, :cond_0

    .line 19
    .line 20
    sget-object v5, Lf01/g;->y:Ljava/lang/String;

    .line 21
    .line 22
    invoke-virtual {v1, v5}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v1, v3}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1, v0}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v1, v2}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v1}, Lu01/a0;->flush()V

    .line 35
    .line 36
    .line 37
    :cond_0
    iget v1, p1, Lf01/c;->h:I

    .line 38
    .line 39
    if-gtz v1, :cond_1

    .line 40
    .line 41
    iget-object v1, p1, Lf01/c;->g:La8/b;

    .line 42
    .line 43
    if-eqz v1, :cond_2

    .line 44
    .line 45
    :cond_1
    iput-boolean v4, p1, Lf01/c;->f:Z

    .line 46
    .line 47
    return-void

    .line 48
    :cond_2
    iget-object v1, p1, Lf01/c;->g:La8/b;

    .line 49
    .line 50
    if-eqz v1, :cond_3

    .line 51
    .line 52
    invoke-virtual {v1}, La8/b;->g()V

    .line 53
    .line 54
    .line 55
    :cond_3
    const/4 v1, 0x0

    .line 56
    :goto_0
    const/4 v5, 0x2

    .line 57
    if-ge v1, v5, :cond_4

    .line 58
    .line 59
    iget-object v5, p1, Lf01/c;->c:Ljava/util/ArrayList;

    .line 60
    .line 61
    invoke-virtual {v5, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v5

    .line 65
    check-cast v5, Lu01/y;

    .line 66
    .line 67
    iget-object v6, p0, Lf01/g;->e:Lf01/f;

    .line 68
    .line 69
    invoke-static {v6, v5}, Le01/e;->d(Lf01/f;Lu01/y;)V

    .line 70
    .line 71
    .line 72
    iget-wide v5, p0, Lf01/g;->j:J

    .line 73
    .line 74
    iget-object v7, p1, Lf01/c;->b:[J

    .line 75
    .line 76
    aget-wide v8, v7, v1

    .line 77
    .line 78
    sub-long/2addr v5, v8

    .line 79
    iput-wide v5, p0, Lf01/g;->j:J

    .line 80
    .line 81
    const-wide/16 v5, 0x0

    .line 82
    .line 83
    aput-wide v5, v7, v1

    .line 84
    .line 85
    add-int/lit8 v1, v1, 0x1

    .line 86
    .line 87
    goto :goto_0

    .line 88
    :cond_4
    iget p1, p0, Lf01/g;->m:I

    .line 89
    .line 90
    add-int/2addr p1, v4

    .line 91
    iput p1, p0, Lf01/g;->m:I

    .line 92
    .line 93
    iget-object p1, p0, Lf01/g;->k:Lu01/a0;

    .line 94
    .line 95
    if-eqz p1, :cond_5

    .line 96
    .line 97
    sget-object v1, Lf01/g;->z:Ljava/lang/String;

    .line 98
    .line 99
    invoke-virtual {p1, v1}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 100
    .line 101
    .line 102
    invoke-virtual {p1, v3}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 103
    .line 104
    .line 105
    invoke-virtual {p1, v0}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 106
    .line 107
    .line 108
    invoke-virtual {p1, v2}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 109
    .line 110
    .line 111
    :cond_5
    iget-object p1, p0, Lf01/g;->l:Ljava/util/LinkedHashMap;

    .line 112
    .line 113
    invoke-virtual {p1, v0}, Ljava/util/AbstractMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    invoke-virtual {p0}, Lf01/g;->h()Z

    .line 117
    .line 118
    .line 119
    move-result p1

    .line 120
    if-eqz p1, :cond_6

    .line 121
    .line 122
    iget-object p1, p0, Lf01/g;->u:Lg01/b;

    .line 123
    .line 124
    iget-object p0, p0, Lf01/g;->v:Lf01/e;

    .line 125
    .line 126
    invoke-static {p1, p0}, Lg01/b;->e(Lg01/b;Lg01/a;)V

    .line 127
    .line 128
    .line 129
    :cond_6
    return-void
.end method

.method public final E()V
    .locals 4

    .line 1
    :goto_0
    iget-wide v0, p0, Lf01/g;->j:J

    .line 2
    .line 3
    iget-wide v2, p0, Lf01/g;->f:J

    .line 4
    .line 5
    cmp-long v0, v0, v2

    .line 6
    .line 7
    if-lez v0, :cond_2

    .line 8
    .line 9
    iget-object v0, p0, Lf01/g;->l:Ljava/util/LinkedHashMap;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    const-string v2, "next(...)"

    .line 30
    .line 31
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    check-cast v1, Lf01/c;

    .line 35
    .line 36
    iget-boolean v2, v1, Lf01/c;->f:Z

    .line 37
    .line 38
    if-nez v2, :cond_0

    .line 39
    .line 40
    invoke-virtual {p0, v1}, Lf01/g;->B(Lf01/c;)V

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    return-void

    .line 45
    :cond_2
    const/4 v0, 0x0

    .line 46
    iput-boolean v0, p0, Lf01/g;->r:Z

    .line 47
    .line 48
    return-void
.end method

.method public final declared-synchronized a()V
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lf01/g;->q:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    monitor-exit p0

    .line 7
    return-void

    .line 8
    :cond_0
    :try_start_1
    const-string v0, "cache is closed"

    .line 9
    .line 10
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 11
    .line 12
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    throw v1

    .line 16
    :catchall_0
    move-exception v0

    .line 17
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 18
    throw v0
.end method

.method public final declared-synchronized b(La8/b;Z)V
    .locals 9

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p1, La8/b;->f:Ljava/lang/Object;

    .line 3
    .line 4
    check-cast v0, Lf01/c;

    .line 5
    .line 6
    iget-object v1, v0, Lf01/c;->g:La8/b;

    .line 7
    .line 8
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-eqz v1, :cond_e

    .line 13
    .line 14
    const/4 v1, 0x2

    .line 15
    const/4 v2, 0x0

    .line 16
    if-eqz p2, :cond_2

    .line 17
    .line 18
    iget-boolean v3, v0, Lf01/c;->e:Z

    .line 19
    .line 20
    if-nez v3, :cond_2

    .line 21
    .line 22
    move v3, v2

    .line 23
    :goto_0
    if-ge v3, v1, :cond_2

    .line 24
    .line 25
    iget-object v4, p1, La8/b;->g:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v4, [Z

    .line 28
    .line 29
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    aget-boolean v4, v4, v3

    .line 33
    .line 34
    if-eqz v4, :cond_1

    .line 35
    .line 36
    iget-object v4, p0, Lf01/g;->e:Lf01/f;

    .line 37
    .line 38
    iget-object v5, v0, Lf01/c;->d:Ljava/util/ArrayList;

    .line 39
    .line 40
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v5

    .line 44
    check-cast v5, Lu01/y;

    .line 45
    .line 46
    invoke-virtual {v4, v5}, Lu01/k;->j(Lu01/y;)Z

    .line 47
    .line 48
    .line 49
    move-result v4

    .line 50
    if-nez v4, :cond_0

    .line 51
    .line 52
    invoke-virtual {p1}, La8/b;->b()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 53
    .line 54
    .line 55
    monitor-exit p0

    .line 56
    return-void

    .line 57
    :catchall_0
    move-exception p1

    .line 58
    goto/16 :goto_7

    .line 59
    .line 60
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_1
    :try_start_1
    invoke-virtual {p1}, La8/b;->b()V

    .line 64
    .line 65
    .line 66
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 67
    .line 68
    new-instance p2, Ljava/lang/StringBuilder;

    .line 69
    .line 70
    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    .line 71
    .line 72
    .line 73
    const-string v0, "Newly created entry didn\'t create value for index "

    .line 74
    .line 75
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    invoke-virtual {p2, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw p1

    .line 89
    :cond_2
    move p1, v2

    .line 90
    :goto_1
    if-ge p1, v1, :cond_6

    .line 91
    .line 92
    iget-object v3, v0, Lf01/c;->d:Ljava/util/ArrayList;

    .line 93
    .line 94
    invoke-virtual {v3, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v3

    .line 98
    check-cast v3, Lu01/y;

    .line 99
    .line 100
    if-eqz p2, :cond_4

    .line 101
    .line 102
    iget-boolean v4, v0, Lf01/c;->f:Z

    .line 103
    .line 104
    if-nez v4, :cond_4

    .line 105
    .line 106
    iget-object v4, p0, Lf01/g;->e:Lf01/f;

    .line 107
    .line 108
    invoke-virtual {v4, v3}, Lu01/k;->j(Lu01/y;)Z

    .line 109
    .line 110
    .line 111
    move-result v4

    .line 112
    if-eqz v4, :cond_5

    .line 113
    .line 114
    iget-object v4, v0, Lf01/c;->c:Ljava/util/ArrayList;

    .line 115
    .line 116
    invoke-virtual {v4, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v4

    .line 120
    check-cast v4, Lu01/y;

    .line 121
    .line 122
    iget-object v5, p0, Lf01/g;->e:Lf01/f;

    .line 123
    .line 124
    invoke-virtual {v5, v3, v4}, Lu01/l;->b(Lu01/y;Lu01/y;)V

    .line 125
    .line 126
    .line 127
    iget-object v3, v0, Lf01/c;->b:[J

    .line 128
    .line 129
    aget-wide v5, v3, p1

    .line 130
    .line 131
    iget-object v3, p0, Lf01/g;->e:Lf01/f;

    .line 132
    .line 133
    invoke-virtual {v3, v4}, Lu01/k;->l(Lu01/y;)Li5/f;

    .line 134
    .line 135
    .line 136
    move-result-object v3

    .line 137
    iget-object v3, v3, Li5/f;->e:Ljava/lang/Object;

    .line 138
    .line 139
    check-cast v3, Ljava/lang/Long;

    .line 140
    .line 141
    if-eqz v3, :cond_3

    .line 142
    .line 143
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 144
    .line 145
    .line 146
    move-result-wide v3

    .line 147
    goto :goto_2

    .line 148
    :cond_3
    const-wide/16 v3, 0x0

    .line 149
    .line 150
    :goto_2
    iget-object v7, v0, Lf01/c;->b:[J

    .line 151
    .line 152
    aput-wide v3, v7, p1

    .line 153
    .line 154
    iget-wide v7, p0, Lf01/g;->j:J

    .line 155
    .line 156
    sub-long/2addr v7, v5

    .line 157
    add-long/2addr v7, v3

    .line 158
    iput-wide v7, p0, Lf01/g;->j:J

    .line 159
    .line 160
    goto :goto_3

    .line 161
    :cond_4
    iget-object v4, p0, Lf01/g;->e:Lf01/f;

    .line 162
    .line 163
    invoke-static {v4, v3}, Le01/e;->d(Lf01/f;Lu01/y;)V

    .line 164
    .line 165
    .line 166
    :cond_5
    :goto_3
    add-int/lit8 p1, p1, 0x1

    .line 167
    .line 168
    goto :goto_1

    .line 169
    :cond_6
    const/4 p1, 0x0

    .line 170
    iput-object p1, v0, Lf01/c;->g:La8/b;

    .line 171
    .line 172
    iget-boolean p1, v0, Lf01/c;->f:Z

    .line 173
    .line 174
    if-eqz p1, :cond_7

    .line 175
    .line 176
    invoke-virtual {p0, v0}, Lf01/g;->B(Lf01/c;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 177
    .line 178
    .line 179
    monitor-exit p0

    .line 180
    return-void

    .line 181
    :cond_7
    :try_start_2
    iget p1, p0, Lf01/g;->m:I

    .line 182
    .line 183
    const/4 v1, 0x1

    .line 184
    add-int/2addr p1, v1

    .line 185
    iput p1, p0, Lf01/g;->m:I

    .line 186
    .line 187
    iget-object p1, p0, Lf01/g;->k:Lu01/a0;

    .line 188
    .line 189
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 190
    .line 191
    .line 192
    iget-boolean v3, v0, Lf01/c;->e:Z

    .line 193
    .line 194
    const/16 v4, 0xa

    .line 195
    .line 196
    const/16 v5, 0x20

    .line 197
    .line 198
    if-nez v3, :cond_9

    .line 199
    .line 200
    if-eqz p2, :cond_8

    .line 201
    .line 202
    goto :goto_4

    .line 203
    :cond_8
    iget-object p2, p0, Lf01/g;->l:Ljava/util/LinkedHashMap;

    .line 204
    .line 205
    iget-object v1, v0, Lf01/c;->a:Ljava/lang/String;

    .line 206
    .line 207
    invoke-virtual {p2, v1}, Ljava/util/AbstractMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    sget-object p2, Lf01/g;->z:Ljava/lang/String;

    .line 211
    .line 212
    invoke-virtual {p1, p2}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 213
    .line 214
    .line 215
    invoke-virtual {p1, v5}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 216
    .line 217
    .line 218
    iget-object p2, v0, Lf01/c;->a:Ljava/lang/String;

    .line 219
    .line 220
    invoke-virtual {p1, p2}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 221
    .line 222
    .line 223
    invoke-virtual {p1, v4}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 224
    .line 225
    .line 226
    goto :goto_6

    .line 227
    :cond_9
    :goto_4
    iput-boolean v1, v0, Lf01/c;->e:Z

    .line 228
    .line 229
    sget-object v1, Lf01/g;->x:Ljava/lang/String;

    .line 230
    .line 231
    invoke-virtual {p1, v1}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 232
    .line 233
    .line 234
    invoke-virtual {p1, v5}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 235
    .line 236
    .line 237
    iget-object v1, v0, Lf01/c;->a:Ljava/lang/String;

    .line 238
    .line 239
    invoke-virtual {p1, v1}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 240
    .line 241
    .line 242
    iget-object v1, v0, Lf01/c;->b:[J

    .line 243
    .line 244
    array-length v3, v1

    .line 245
    :goto_5
    if-ge v2, v3, :cond_a

    .line 246
    .line 247
    aget-wide v6, v1, v2

    .line 248
    .line 249
    invoke-virtual {p1, v5}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 250
    .line 251
    .line 252
    invoke-virtual {p1, v6, v7}, Lu01/a0;->N(J)Lu01/g;

    .line 253
    .line 254
    .line 255
    add-int/lit8 v2, v2, 0x1

    .line 256
    .line 257
    goto :goto_5

    .line 258
    :cond_a
    invoke-virtual {p1, v4}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 259
    .line 260
    .line 261
    if-eqz p2, :cond_b

    .line 262
    .line 263
    iget-wide v1, p0, Lf01/g;->t:J

    .line 264
    .line 265
    const-wide/16 v3, 0x1

    .line 266
    .line 267
    add-long/2addr v3, v1

    .line 268
    iput-wide v3, p0, Lf01/g;->t:J

    .line 269
    .line 270
    iput-wide v1, v0, Lf01/c;->i:J

    .line 271
    .line 272
    :cond_b
    :goto_6
    invoke-virtual {p1}, Lu01/a0;->flush()V

    .line 273
    .line 274
    .line 275
    iget-wide p1, p0, Lf01/g;->j:J

    .line 276
    .line 277
    iget-wide v0, p0, Lf01/g;->f:J

    .line 278
    .line 279
    cmp-long p1, p1, v0

    .line 280
    .line 281
    if-gtz p1, :cond_c

    .line 282
    .line 283
    invoke-virtual {p0}, Lf01/g;->h()Z

    .line 284
    .line 285
    .line 286
    move-result p1

    .line 287
    if-eqz p1, :cond_d

    .line 288
    .line 289
    :cond_c
    iget-object p1, p0, Lf01/g;->u:Lg01/b;

    .line 290
    .line 291
    iget-object p2, p0, Lf01/g;->v:Lf01/e;

    .line 292
    .line 293
    invoke-static {p1, p2}, Lg01/b;->e(Lg01/b;Lg01/a;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 294
    .line 295
    .line 296
    :cond_d
    monitor-exit p0

    .line 297
    return-void

    .line 298
    :cond_e
    :try_start_3
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 299
    .line 300
    const-string p2, "Check failed."

    .line 301
    .line 302
    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 303
    .line 304
    .line 305
    throw p1

    .line 306
    :goto_7
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 307
    throw p1
.end method

.method public final declared-synchronized close()V
    .locals 5

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lf01/g;->p:Z

    .line 3
    .line 4
    const/4 v1, 0x1

    .line 5
    if-eqz v0, :cond_4

    .line 6
    .line 7
    iget-boolean v0, p0, Lf01/g;->q:Z

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    goto :goto_2

    .line 12
    :cond_0
    iget-object v0, p0, Lf01/g;->l:Ljava/util/LinkedHashMap;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const-string v2, "<get-values>(...)"

    .line 19
    .line 20
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    new-array v3, v2, [Lf01/c;

    .line 25
    .line 26
    invoke-interface {v0, v3}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    check-cast v0, [Lf01/c;

    .line 31
    .line 32
    array-length v3, v0

    .line 33
    :goto_0
    if-ge v2, v3, :cond_2

    .line 34
    .line 35
    aget-object v4, v0, v2

    .line 36
    .line 37
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    iget-object v4, v4, Lf01/c;->g:La8/b;

    .line 41
    .line 42
    if-eqz v4, :cond_1

    .line 43
    .line 44
    invoke-virtual {v4}, La8/b;->g()V

    .line 45
    .line 46
    .line 47
    goto :goto_1

    .line 48
    :catchall_0
    move-exception v0

    .line 49
    goto :goto_3

    .line 50
    :cond_1
    :goto_1
    add-int/lit8 v2, v2, 0x1

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_2
    invoke-virtual {p0}, Lf01/g;->E()V

    .line 54
    .line 55
    .line 56
    iget-object v0, p0, Lf01/g;->k:Lu01/a0;

    .line 57
    .line 58
    if-eqz v0, :cond_3

    .line 59
    .line 60
    invoke-static {v0}, Le01/e;->b(Ljava/io/Closeable;)V

    .line 61
    .line 62
    .line 63
    :cond_3
    const/4 v0, 0x0

    .line 64
    iput-object v0, p0, Lf01/g;->k:Lu01/a0;

    .line 65
    .line 66
    iput-boolean v1, p0, Lf01/g;->q:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 67
    .line 68
    monitor-exit p0

    .line 69
    return-void

    .line 70
    :cond_4
    :goto_2
    :try_start_1
    iput-boolean v1, p0, Lf01/g;->q:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 71
    .line 72
    monitor-exit p0

    .line 73
    return-void

    .line 74
    :goto_3
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 75
    throw v0
.end method

.method public final declared-synchronized d(JLjava/lang/String;)La8/b;
    .locals 5

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    const-string v0, "key"

    .line 3
    .line 4
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Lf01/g;->g()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lf01/g;->a()V

    .line 11
    .line 12
    .line 13
    invoke-static {p3}, Lf01/g;->H(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lf01/g;->l:Ljava/util/LinkedHashMap;

    .line 17
    .line 18
    invoke-virtual {v0, p3}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    check-cast v0, Lf01/c;

    .line 23
    .line 24
    const-wide/16 v1, -0x1

    .line 25
    .line 26
    cmp-long v1, p1, v1

    .line 27
    .line 28
    const/4 v2, 0x0

    .line 29
    if-eqz v1, :cond_1

    .line 30
    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    iget-wide v3, v0, Lf01/c;->i:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 34
    .line 35
    cmp-long p1, v3, p1

    .line 36
    .line 37
    if-eqz p1, :cond_1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :catchall_0
    move-exception p1

    .line 41
    goto :goto_3

    .line 42
    :cond_0
    :goto_0
    monitor-exit p0

    .line 43
    return-object v2

    .line 44
    :cond_1
    if-eqz v0, :cond_2

    .line 45
    .line 46
    :try_start_1
    iget-object p1, v0, Lf01/c;->g:La8/b;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_2
    move-object p1, v2

    .line 50
    :goto_1
    if-eqz p1, :cond_3

    .line 51
    .line 52
    monitor-exit p0

    .line 53
    return-object v2

    .line 54
    :cond_3
    if-eqz v0, :cond_4

    .line 55
    .line 56
    :try_start_2
    iget p1, v0, Lf01/c;->h:I
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 57
    .line 58
    if-eqz p1, :cond_4

    .line 59
    .line 60
    monitor-exit p0

    .line 61
    return-object v2

    .line 62
    :cond_4
    :try_start_3
    iget-boolean p1, p0, Lf01/g;->r:Z

    .line 63
    .line 64
    if-nez p1, :cond_8

    .line 65
    .line 66
    iget-boolean p1, p0, Lf01/g;->s:Z

    .line 67
    .line 68
    if-eqz p1, :cond_5

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_5
    iget-object p1, p0, Lf01/g;->k:Lu01/a0;

    .line 72
    .line 73
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    sget-object p2, Lf01/g;->y:Ljava/lang/String;

    .line 77
    .line 78
    invoke-virtual {p1, p2}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 79
    .line 80
    .line 81
    const/16 p2, 0x20

    .line 82
    .line 83
    invoke-virtual {p1, p2}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 84
    .line 85
    .line 86
    invoke-interface {p1, p3}, Lu01/g;->z(Ljava/lang/String;)Lu01/g;

    .line 87
    .line 88
    .line 89
    const/16 p2, 0xa

    .line 90
    .line 91
    invoke-interface {p1, p2}, Lu01/g;->writeByte(I)Lu01/g;

    .line 92
    .line 93
    .line 94
    invoke-virtual {p1}, Lu01/a0;->flush()V

    .line 95
    .line 96
    .line 97
    iget-boolean p1, p0, Lf01/g;->n:Z
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 98
    .line 99
    if-eqz p1, :cond_6

    .line 100
    .line 101
    monitor-exit p0

    .line 102
    return-object v2

    .line 103
    :cond_6
    if-nez v0, :cond_7

    .line 104
    .line 105
    :try_start_4
    new-instance v0, Lf01/c;

    .line 106
    .line 107
    invoke-direct {v0, p0, p3}, Lf01/c;-><init>(Lf01/g;Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    iget-object p1, p0, Lf01/g;->l:Ljava/util/LinkedHashMap;

    .line 111
    .line 112
    invoke-interface {p1, p3, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    :cond_7
    new-instance p1, La8/b;

    .line 116
    .line 117
    invoke-direct {p1, p0, v0}, La8/b;-><init>(Lf01/g;Lf01/c;)V

    .line 118
    .line 119
    .line 120
    iput-object p1, v0, Lf01/c;->g:La8/b;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 121
    .line 122
    monitor-exit p0

    .line 123
    return-object p1

    .line 124
    :cond_8
    :goto_2
    :try_start_5
    iget-object p1, p0, Lf01/g;->u:Lg01/b;

    .line 125
    .line 126
    iget-object p2, p0, Lf01/g;->v:Lf01/e;

    .line 127
    .line 128
    invoke-static {p1, p2}, Lg01/b;->e(Lg01/b;Lg01/a;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 129
    .line 130
    .line 131
    monitor-exit p0

    .line 132
    return-object v2

    .line 133
    :goto_3
    :try_start_6
    monitor-exit p0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 134
    throw p1
.end method

.method public final declared-synchronized f(Ljava/lang/String;)Lf01/d;
    .locals 3

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    const-string v0, "key"

    .line 3
    .line 4
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Lf01/g;->g()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lf01/g;->a()V

    .line 11
    .line 12
    .line 13
    invoke-static {p1}, Lf01/g;->H(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lf01/g;->l:Ljava/util/LinkedHashMap;

    .line 17
    .line 18
    invoke-virtual {v0, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    check-cast v0, Lf01/c;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    if-nez v0, :cond_0

    .line 26
    .line 27
    monitor-exit p0

    .line 28
    return-object v1

    .line 29
    :cond_0
    :try_start_1
    invoke-virtual {v0}, Lf01/c;->a()Lf01/d;

    .line 30
    .line 31
    .line 32
    move-result-object v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 33
    if-nez v0, :cond_1

    .line 34
    .line 35
    monitor-exit p0

    .line 36
    return-object v1

    .line 37
    :cond_1
    :try_start_2
    iget v1, p0, Lf01/g;->m:I

    .line 38
    .line 39
    add-int/lit8 v1, v1, 0x1

    .line 40
    .line 41
    iput v1, p0, Lf01/g;->m:I

    .line 42
    .line 43
    iget-object v1, p0, Lf01/g;->k:Lu01/a0;

    .line 44
    .line 45
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    sget-object v2, Lf01/g;->A:Ljava/lang/String;

    .line 49
    .line 50
    invoke-virtual {v1, v2}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 51
    .line 52
    .line 53
    const/16 v2, 0x20

    .line 54
    .line 55
    invoke-virtual {v1, v2}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 56
    .line 57
    .line 58
    invoke-interface {v1, p1}, Lu01/g;->z(Ljava/lang/String;)Lu01/g;

    .line 59
    .line 60
    .line 61
    const/16 p1, 0xa

    .line 62
    .line 63
    invoke-interface {v1, p1}, Lu01/g;->writeByte(I)Lu01/g;

    .line 64
    .line 65
    .line 66
    invoke-virtual {p0}, Lf01/g;->h()Z

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    if-eqz p1, :cond_2

    .line 71
    .line 72
    iget-object p1, p0, Lf01/g;->u:Lg01/b;

    .line 73
    .line 74
    iget-object v1, p0, Lf01/g;->v:Lf01/e;

    .line 75
    .line 76
    invoke-static {p1, v1}, Lg01/b;->e(Lg01/b;Lg01/a;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 77
    .line 78
    .line 79
    goto :goto_0

    .line 80
    :catchall_0
    move-exception p1

    .line 81
    goto :goto_1

    .line 82
    :cond_2
    :goto_0
    monitor-exit p0

    .line 83
    return-object v0

    .line 84
    :goto_1
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 85
    throw p1
.end method

.method public final declared-synchronized flush()V
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lf01/g;->p:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    monitor-exit p0

    .line 7
    return-void

    .line 8
    :cond_0
    :try_start_1
    invoke-virtual {p0}, Lf01/g;->a()V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lf01/g;->E()V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lf01/g;->k:Lu01/a0;

    .line 15
    .line 16
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Lu01/a0;->flush()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 20
    .line 21
    .line 22
    monitor-exit p0

    .line 23
    return-void

    .line 24
    :catchall_0
    move-exception v0

    .line 25
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 26
    throw v0
.end method

.method public final declared-synchronized g()V
    .locals 7

    .line 1
    const-string v0, "DiskLruCache "

    .line 2
    .line 3
    monitor-enter p0

    .line 4
    :try_start_0
    sget-object v1, Le01/g;->a:Ljava/util/TimeZone;

    .line 5
    .line 6
    iget-boolean v1, p0, Lf01/g;->p:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    monitor-exit p0

    .line 11
    return-void

    .line 12
    :cond_0
    :try_start_1
    iget-object v1, p0, Lf01/g;->e:Lf01/f;

    .line 13
    .line 14
    iget-object v2, p0, Lf01/g;->i:Lu01/y;

    .line 15
    .line 16
    invoke-virtual {v1, v2}, Lu01/k;->j(Lu01/y;)Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_2

    .line 21
    .line 22
    iget-object v1, p0, Lf01/g;->e:Lf01/f;

    .line 23
    .line 24
    iget-object v2, p0, Lf01/g;->g:Lu01/y;

    .line 25
    .line 26
    invoke-virtual {v1, v2}, Lu01/k;->j(Lu01/y;)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    iget-object v1, p0, Lf01/g;->e:Lf01/f;

    .line 33
    .line 34
    iget-object v2, p0, Lf01/g;->i:Lu01/y;

    .line 35
    .line 36
    invoke-virtual {v1, v2}, Lu01/k;->h(Lu01/y;)V

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :catchall_0
    move-exception v0

    .line 41
    goto/16 :goto_6

    .line 42
    .line 43
    :cond_1
    iget-object v1, p0, Lf01/g;->e:Lf01/f;

    .line 44
    .line 45
    iget-object v2, p0, Lf01/g;->i:Lu01/y;

    .line 46
    .line 47
    iget-object v3, p0, Lf01/g;->g:Lu01/y;

    .line 48
    .line 49
    invoke-virtual {v1, v2, v3}, Lu01/l;->b(Lu01/y;Lu01/y;)V

    .line 50
    .line 51
    .line 52
    :cond_2
    :goto_0
    iget-object v1, p0, Lf01/g;->e:Lf01/f;

    .line 53
    .line 54
    iget-object v2, p0, Lf01/g;->i:Lu01/y;

    .line 55
    .line 56
    sget-object v3, Le01/e;->a:[B

    .line 57
    .line 58
    const-string v3, "<this>"

    .line 59
    .line 60
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    const-string v3, "file"

    .line 64
    .line 65
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    const/4 v3, 0x0

    .line 69
    invoke-virtual {v1, v2, v3}, Lf01/f;->E(Lu01/y;Z)Lu01/f0;

    .line 70
    .line 71
    .line 72
    move-result-object v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 73
    const/4 v5, 0x1

    .line 74
    :try_start_2
    invoke-virtual {v1, v2}, Lu01/l;->g(Lu01/y;)V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 75
    .line 76
    .line 77
    if-eqz v4, :cond_3

    .line 78
    .line 79
    :try_start_3
    invoke-interface {v4}, Ljava/io/Closeable;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 80
    .line 81
    .line 82
    :catchall_1
    :cond_3
    move v1, v5

    .line 83
    goto :goto_4

    .line 84
    :catchall_2
    move-exception v6

    .line 85
    if-eqz v4, :cond_5

    .line 86
    .line 87
    :try_start_4
    invoke-interface {v4}, Ljava/io/Closeable;->close()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 88
    .line 89
    .line 90
    goto :goto_3

    .line 91
    :catchall_3
    move-exception v4

    .line 92
    :try_start_5
    invoke-static {v6, v4}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 93
    .line 94
    .line 95
    goto :goto_3

    .line 96
    :catch_0
    if-eqz v4, :cond_4

    .line 97
    .line 98
    :try_start_6
    invoke-interface {v4}, Ljava/io/Closeable;->close()V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_4

    .line 99
    .line 100
    .line 101
    goto :goto_2

    .line 102
    :catchall_4
    move-exception v4

    .line 103
    :goto_1
    move-object v6, v4

    .line 104
    goto :goto_3

    .line 105
    :cond_4
    :goto_2
    const/4 v4, 0x0

    .line 106
    goto :goto_1

    .line 107
    :cond_5
    :goto_3
    if-nez v6, :cond_7

    .line 108
    .line 109
    :try_start_7
    invoke-virtual {v1, v2}, Lu01/l;->g(Lu01/y;)V

    .line 110
    .line 111
    .line 112
    move v1, v3

    .line 113
    :goto_4
    iput-boolean v1, p0, Lf01/g;->o:Z

    .line 114
    .line 115
    iget-object v1, p0, Lf01/g;->e:Lf01/f;

    .line 116
    .line 117
    iget-object v2, p0, Lf01/g;->g:Lu01/y;

    .line 118
    .line 119
    invoke-virtual {v1, v2}, Lu01/k;->j(Lu01/y;)Z

    .line 120
    .line 121
    .line 122
    move-result v1
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 123
    if-eqz v1, :cond_6

    .line 124
    .line 125
    :try_start_8
    invoke-virtual {p0}, Lf01/g;->k()V

    .line 126
    .line 127
    .line 128
    invoke-virtual {p0}, Lf01/g;->j()V

    .line 129
    .line 130
    .line 131
    iput-boolean v5, p0, Lf01/g;->p:Z
    :try_end_8
    .catch Ljava/io/IOException; {:try_start_8 .. :try_end_8} :catch_1
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 132
    .line 133
    monitor-exit p0

    .line 134
    return-void

    .line 135
    :catch_1
    move-exception v1

    .line 136
    :try_start_9
    sget-object v2, Ln01/d;->a:Ln01/b;

    .line 137
    .line 138
    sget-object v2, Ln01/d;->a:Ln01/b;

    .line 139
    .line 140
    new-instance v4, Ljava/lang/StringBuilder;

    .line 141
    .line 142
    invoke-direct {v4, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    iget-object v0, p0, Lf01/g;->d:Lu01/y;

    .line 146
    .line 147
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 148
    .line 149
    .line 150
    const-string v0, " is corrupt: "

    .line 151
    .line 152
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 153
    .line 154
    .line 155
    invoke-virtual {v1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 160
    .line 161
    .line 162
    const-string v0, ", removing"

    .line 163
    .line 164
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 165
    .line 166
    .line 167
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object v0

    .line 171
    const/4 v4, 0x5

    .line 172
    invoke-virtual {v2, v4, v0, v1}, Ln01/b;->c(ILjava/lang/String;Ljava/lang/Throwable;)V
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_0

    .line 173
    .line 174
    .line 175
    :try_start_a
    invoke-virtual {p0}, Lf01/g;->close()V

    .line 176
    .line 177
    .line 178
    iget-object v0, p0, Lf01/g;->e:Lf01/f;

    .line 179
    .line 180
    iget-object v1, p0, Lf01/g;->d:Lu01/y;

    .line 181
    .line 182
    invoke-static {v0, v1}, Le01/e;->c(Lu01/k;Lu01/y;)V
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_5

    .line 183
    .line 184
    .line 185
    :try_start_b
    iput-boolean v3, p0, Lf01/g;->q:Z

    .line 186
    .line 187
    goto :goto_5

    .line 188
    :catchall_5
    move-exception v0

    .line 189
    iput-boolean v3, p0, Lf01/g;->q:Z

    .line 190
    .line 191
    throw v0

    .line 192
    :cond_6
    :goto_5
    invoke-virtual {p0}, Lf01/g;->q()V

    .line 193
    .line 194
    .line 195
    iput-boolean v5, p0, Lf01/g;->p:Z
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_0

    .line 196
    .line 197
    monitor-exit p0

    .line 198
    return-void

    .line 199
    :cond_7
    :try_start_c
    throw v6

    .line 200
    :goto_6
    monitor-exit p0
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_0

    .line 201
    throw v0
.end method

.method public final h()Z
    .locals 2

    .line 1
    iget v0, p0, Lf01/g;->m:I

    .line 2
    .line 3
    const/16 v1, 0x7d0

    .line 4
    .line 5
    if-lt v0, v1, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lf01/g;->l:Ljava/util/LinkedHashMap;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/util/AbstractMap;->size()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-lt v0, p0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    return p0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    return p0
.end method

.method public final j()V
    .locals 10

    .line 1
    iget-object v0, p0, Lf01/g;->h:Lu01/y;

    .line 2
    .line 3
    iget-object v1, p0, Lf01/g;->e:Lf01/f;

    .line 4
    .line 5
    invoke-static {v1, v0}, Le01/e;->d(Lf01/f;Lu01/y;)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lf01/g;->l:Ljava/util/LinkedHashMap;

    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_3

    .line 23
    .line 24
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    const-string v3, "next(...)"

    .line 29
    .line 30
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    check-cast v2, Lf01/c;

    .line 34
    .line 35
    iget-object v3, v2, Lf01/c;->g:La8/b;

    .line 36
    .line 37
    const/4 v4, 0x2

    .line 38
    const/4 v5, 0x0

    .line 39
    if-nez v3, :cond_1

    .line 40
    .line 41
    :goto_1
    if-ge v5, v4, :cond_0

    .line 42
    .line 43
    iget-wide v6, p0, Lf01/g;->j:J

    .line 44
    .line 45
    iget-object v3, v2, Lf01/c;->b:[J

    .line 46
    .line 47
    aget-wide v8, v3, v5

    .line 48
    .line 49
    add-long/2addr v6, v8

    .line 50
    iput-wide v6, p0, Lf01/g;->j:J

    .line 51
    .line 52
    add-int/lit8 v5, v5, 0x1

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_1
    const/4 v3, 0x0

    .line 56
    iput-object v3, v2, Lf01/c;->g:La8/b;

    .line 57
    .line 58
    :goto_2
    if-ge v5, v4, :cond_2

    .line 59
    .line 60
    iget-object v3, v2, Lf01/c;->c:Ljava/util/ArrayList;

    .line 61
    .line 62
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    check-cast v3, Lu01/y;

    .line 67
    .line 68
    invoke-static {v1, v3}, Le01/e;->d(Lf01/f;Lu01/y;)V

    .line 69
    .line 70
    .line 71
    iget-object v3, v2, Lf01/c;->d:Ljava/util/ArrayList;

    .line 72
    .line 73
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v3

    .line 77
    check-cast v3, Lu01/y;

    .line 78
    .line 79
    invoke-static {v1, v3}, Le01/e;->d(Lf01/f;Lu01/y;)V

    .line 80
    .line 81
    .line 82
    add-int/lit8 v5, v5, 0x1

    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_2
    invoke-interface {v0}, Ljava/util/Iterator;->remove()V

    .line 86
    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_3
    return-void
.end method

.method public final k()V
    .locals 13

    .line 1
    const-string v0, ", "

    .line 2
    .line 3
    const-string v1, "unexpected journal header: ["

    .line 4
    .line 5
    iget-object v2, p0, Lf01/g;->e:Lf01/f;

    .line 6
    .line 7
    iget-object v3, p0, Lf01/g;->g:Lu01/y;

    .line 8
    .line 9
    invoke-virtual {v2, v3}, Lu01/l;->H(Lu01/y;)Lu01/h0;

    .line 10
    .line 11
    .line 12
    move-result-object v4

    .line 13
    invoke-static {v4}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 14
    .line 15
    .line 16
    move-result-object v4

    .line 17
    const-wide v5, 0x7fffffffffffffffL

    .line 18
    .line 19
    .line 20
    .line 21
    .line 22
    :try_start_0
    invoke-virtual {v4, v5, v6}, Lu01/b0;->x(J)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v7

    .line 26
    invoke-virtual {v4, v5, v6}, Lu01/b0;->x(J)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v8

    .line 30
    invoke-virtual {v4, v5, v6}, Lu01/b0;->x(J)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v9

    .line 34
    invoke-virtual {v4, v5, v6}, Lu01/b0;->x(J)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v10

    .line 38
    invoke-virtual {v4, v5, v6}, Lu01/b0;->x(J)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v11

    .line 42
    const-string v12, "libcore.io.DiskLruCache"

    .line 43
    .line 44
    invoke-virtual {v12, v7}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v12

    .line 48
    if-eqz v12, :cond_2

    .line 49
    .line 50
    const-string v12, "1"

    .line 51
    .line 52
    invoke-virtual {v12, v8}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v12

    .line 56
    if-eqz v12, :cond_2

    .line 57
    .line 58
    const v12, 0x31191

    .line 59
    .line 60
    .line 61
    invoke-static {v12}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v12

    .line 65
    invoke-static {v12, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v9

    .line 69
    if-eqz v9, :cond_2

    .line 70
    .line 71
    const/4 v9, 0x2

    .line 72
    invoke-static {v9}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v9

    .line 76
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v9

    .line 80
    if-eqz v9, :cond_2

    .line 81
    .line 82
    invoke-virtual {v11}, Ljava/lang/String;->length()I

    .line 83
    .line 84
    .line 85
    move-result v9
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 86
    if-gtz v9, :cond_2

    .line 87
    .line 88
    const/4 v0, 0x0

    .line 89
    :goto_0
    :try_start_1
    invoke-virtual {v4, v5, v6}, Lu01/b0;->x(J)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    invoke-virtual {p0, v1}, Lf01/g;->l(Ljava/lang/String;)V
    :try_end_1
    .catch Ljava/io/EOFException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 94
    .line 95
    .line 96
    add-int/lit8 v0, v0, 0x1

    .line 97
    .line 98
    goto :goto_0

    .line 99
    :catchall_0
    move-exception p0

    .line 100
    goto :goto_2

    .line 101
    :catch_0
    :try_start_2
    iget-object v1, p0, Lf01/g;->l:Ljava/util/LinkedHashMap;

    .line 102
    .line 103
    invoke-virtual {v1}, Ljava/util/AbstractMap;->size()I

    .line 104
    .line 105
    .line 106
    move-result v1

    .line 107
    sub-int/2addr v0, v1

    .line 108
    iput v0, p0, Lf01/g;->m:I

    .line 109
    .line 110
    invoke-virtual {v4}, Lu01/b0;->Z()Z

    .line 111
    .line 112
    .line 113
    move-result v0

    .line 114
    if-nez v0, :cond_0

    .line 115
    .line 116
    invoke-virtual {p0}, Lf01/g;->q()V

    .line 117
    .line 118
    .line 119
    goto :goto_1

    .line 120
    :cond_0
    iget-object v0, p0, Lf01/g;->k:Lu01/a0;

    .line 121
    .line 122
    if-eqz v0, :cond_1

    .line 123
    .line 124
    invoke-static {v0}, Le01/e;->b(Ljava/io/Closeable;)V

    .line 125
    .line 126
    .line 127
    :cond_1
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 128
    .line 129
    .line 130
    const-string v0, "file"

    .line 131
    .line 132
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {v2, v3}, Lu01/l;->a(Lu01/y;)Lu01/f0;

    .line 136
    .line 137
    .line 138
    move-result-object v0

    .line 139
    new-instance v1, Lf01/h;

    .line 140
    .line 141
    new-instance v2, Le81/w;

    .line 142
    .line 143
    const/4 v3, 0x4

    .line 144
    invoke-direct {v2, p0, v3}, Le81/w;-><init>(Ljava/lang/Object;I)V

    .line 145
    .line 146
    .line 147
    invoke-direct {v1, v0, v2}, Lf01/h;-><init>(Lu01/f0;Lay0/k;)V

    .line 148
    .line 149
    .line 150
    invoke-static {v1}, Lu01/b;->b(Lu01/f0;)Lu01/a0;

    .line 151
    .line 152
    .line 153
    move-result-object v0

    .line 154
    iput-object v0, p0, Lf01/g;->k:Lu01/a0;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 155
    .line 156
    :goto_1
    :try_start_3
    invoke-virtual {v4}, Lu01/b0;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 157
    .line 158
    .line 159
    const/4 p0, 0x0

    .line 160
    goto :goto_3

    .line 161
    :catchall_1
    move-exception p0

    .line 162
    goto :goto_3

    .line 163
    :cond_2
    :try_start_4
    new-instance p0, Ljava/io/IOException;

    .line 164
    .line 165
    new-instance v2, Ljava/lang/StringBuilder;

    .line 166
    .line 167
    invoke-direct {v2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    invoke-virtual {v2, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 171
    .line 172
    .line 173
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 174
    .line 175
    .line 176
    invoke-virtual {v2, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 177
    .line 178
    .line 179
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 180
    .line 181
    .line 182
    invoke-virtual {v2, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 183
    .line 184
    .line 185
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 186
    .line 187
    .line 188
    invoke-virtual {v2, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 189
    .line 190
    .line 191
    const/16 v0, 0x5d

    .line 192
    .line 193
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 194
    .line 195
    .line 196
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object v0

    .line 200
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    throw p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 204
    :goto_2
    :try_start_5
    invoke-virtual {v4}, Lu01/b0;->close()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 205
    .line 206
    .line 207
    goto :goto_3

    .line 208
    :catchall_2
    move-exception v0

    .line 209
    invoke-static {p0, v0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 210
    .line 211
    .line 212
    :goto_3
    if-nez p0, :cond_3

    .line 213
    .line 214
    return-void

    .line 215
    :cond_3
    throw p0
.end method

.method public final l(Ljava/lang/String;)V
    .locals 11

    .line 1
    const/4 v0, 0x6

    .line 2
    const/16 v1, 0x20

    .line 3
    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-static {p1, v1, v2, v0}, Lly0/p;->J(Ljava/lang/CharSequence;CII)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const-string v3, "unexpected journal line: "

    .line 10
    .line 11
    const/4 v4, -0x1

    .line 12
    if-eq v0, v4, :cond_8

    .line 13
    .line 14
    add-int/lit8 v5, v0, 0x1

    .line 15
    .line 16
    const/4 v6, 0x4

    .line 17
    invoke-static {p1, v1, v5, v6}, Lly0/p;->J(Ljava/lang/CharSequence;CII)I

    .line 18
    .line 19
    .line 20
    move-result v6

    .line 21
    iget-object v7, p0, Lf01/g;->l:Ljava/util/LinkedHashMap;

    .line 22
    .line 23
    const-string v8, "substring(...)"

    .line 24
    .line 25
    if-ne v6, v4, :cond_0

    .line 26
    .line 27
    invoke-virtual {p1, v5}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v5

    .line 31
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    sget-object v9, Lf01/g;->z:Ljava/lang/String;

    .line 35
    .line 36
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 37
    .line 38
    .line 39
    move-result v10

    .line 40
    if-ne v0, v10, :cond_1

    .line 41
    .line 42
    invoke-static {p1, v9, v2}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 43
    .line 44
    .line 45
    move-result v9

    .line 46
    if-eqz v9, :cond_1

    .line 47
    .line 48
    invoke-virtual {v7, v5}, Ljava/util/AbstractMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    :cond_0
    invoke-virtual {p1, v5, v6}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v5

    .line 56
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    :cond_1
    invoke-virtual {v7, v5}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v9

    .line 63
    check-cast v9, Lf01/c;

    .line 64
    .line 65
    if-nez v9, :cond_2

    .line 66
    .line 67
    new-instance v9, Lf01/c;

    .line 68
    .line 69
    invoke-direct {v9, p0, v5}, Lf01/c;-><init>(Lf01/g;Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    invoke-interface {v7, v5, v9}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    :cond_2
    if-eq v6, v4, :cond_4

    .line 76
    .line 77
    sget-object v5, Lf01/g;->x:Ljava/lang/String;

    .line 78
    .line 79
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 80
    .line 81
    .line 82
    move-result v7

    .line 83
    if-ne v0, v7, :cond_4

    .line 84
    .line 85
    invoke-static {p1, v5, v2}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 86
    .line 87
    .line 88
    move-result v5

    .line 89
    if-eqz v5, :cond_4

    .line 90
    .line 91
    const/4 p0, 0x1

    .line 92
    add-int/2addr v6, p0

    .line 93
    invoke-virtual {p1, v6}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    invoke-static {p1, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    new-array v0, p0, [C

    .line 101
    .line 102
    aput-char v1, v0, v2

    .line 103
    .line 104
    invoke-static {p1, v0}, Lly0/p;->X(Ljava/lang/CharSequence;[C)Ljava/util/List;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    iput-boolean p0, v9, Lf01/c;->e:Z

    .line 109
    .line 110
    const/4 p0, 0x0

    .line 111
    iput-object p0, v9, Lf01/c;->g:La8/b;

    .line 112
    .line 113
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 114
    .line 115
    .line 116
    move-result p0

    .line 117
    iget-object v0, v9, Lf01/c;->j:Lf01/g;

    .line 118
    .line 119
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 120
    .line 121
    .line 122
    const/4 v0, 0x2

    .line 123
    if-ne p0, v0, :cond_3

    .line 124
    .line 125
    :try_start_0
    move-object p0, p1

    .line 126
    check-cast p0, Ljava/util/Collection;

    .line 127
    .line 128
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 129
    .line 130
    .line 131
    move-result p0

    .line 132
    :goto_0
    if-ge v2, p0, :cond_6

    .line 133
    .line 134
    iget-object v0, v9, Lf01/c;->b:[J

    .line 135
    .line 136
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v1

    .line 140
    check-cast v1, Ljava/lang/String;

    .line 141
    .line 142
    invoke-static {v1}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 143
    .line 144
    .line 145
    move-result-wide v4

    .line 146
    aput-wide v4, v0, v2
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 147
    .line 148
    add-int/lit8 v2, v2, 0x1

    .line 149
    .line 150
    goto :goto_0

    .line 151
    :catch_0
    new-instance p0, Ljava/io/IOException;

    .line 152
    .line 153
    new-instance v0, Ljava/lang/StringBuilder;

    .line 154
    .line 155
    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 159
    .line 160
    .line 161
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object p1

    .line 165
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    throw p0

    .line 169
    :cond_3
    new-instance p0, Ljava/io/IOException;

    .line 170
    .line 171
    new-instance v0, Ljava/lang/StringBuilder;

    .line 172
    .line 173
    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 177
    .line 178
    .line 179
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 180
    .line 181
    .line 182
    move-result-object p1

    .line 183
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    throw p0

    .line 187
    :cond_4
    if-ne v6, v4, :cond_5

    .line 188
    .line 189
    sget-object v1, Lf01/g;->y:Ljava/lang/String;

    .line 190
    .line 191
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 192
    .line 193
    .line 194
    move-result v5

    .line 195
    if-ne v0, v5, :cond_5

    .line 196
    .line 197
    invoke-static {p1, v1, v2}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 198
    .line 199
    .line 200
    move-result v1

    .line 201
    if-eqz v1, :cond_5

    .line 202
    .line 203
    new-instance p1, La8/b;

    .line 204
    .line 205
    invoke-direct {p1, p0, v9}, La8/b;-><init>(Lf01/g;Lf01/c;)V

    .line 206
    .line 207
    .line 208
    iput-object p1, v9, Lf01/c;->g:La8/b;

    .line 209
    .line 210
    return-void

    .line 211
    :cond_5
    if-ne v6, v4, :cond_7

    .line 212
    .line 213
    sget-object p0, Lf01/g;->A:Ljava/lang/String;

    .line 214
    .line 215
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 216
    .line 217
    .line 218
    move-result v1

    .line 219
    if-ne v0, v1, :cond_7

    .line 220
    .line 221
    invoke-static {p1, p0, v2}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 222
    .line 223
    .line 224
    move-result p0

    .line 225
    if-eqz p0, :cond_7

    .line 226
    .line 227
    :cond_6
    return-void

    .line 228
    :cond_7
    new-instance p0, Ljava/io/IOException;

    .line 229
    .line 230
    invoke-virtual {v3, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 231
    .line 232
    .line 233
    move-result-object p1

    .line 234
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    throw p0

    .line 238
    :cond_8
    new-instance p0, Ljava/io/IOException;

    .line 239
    .line 240
    invoke-virtual {v3, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 241
    .line 242
    .line 243
    move-result-object p1

    .line 244
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    throw p0
.end method

.method public final declared-synchronized q()V
    .locals 10

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lf01/g;->k:Lu01/a0;

    .line 3
    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {v0}, Lu01/a0;->close()V

    .line 7
    .line 8
    .line 9
    goto :goto_0

    .line 10
    :catchall_0
    move-exception v0

    .line 11
    goto/16 :goto_7

    .line 12
    .line 13
    :cond_0
    :goto_0
    iget-object v0, p0, Lf01/g;->e:Lf01/f;

    .line 14
    .line 15
    iget-object v1, p0, Lf01/g;->h:Lu01/y;

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    invoke-virtual {v0, v1, v2}, Lf01/f;->E(Lu01/y;Z)Lu01/f0;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-static {v0}, Lu01/b;->b(Lu01/f0;)Lu01/a0;

    .line 23
    .line 24
    .line 25
    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 26
    :try_start_1
    const-string v1, "libcore.io.DiskLruCache"

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 29
    .line 30
    .line 31
    const/16 v1, 0xa

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 34
    .line 35
    .line 36
    const-string v3, "1"

    .line 37
    .line 38
    invoke-virtual {v0, v3}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0, v1}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 42
    .line 43
    .line 44
    const v3, 0x31191

    .line 45
    .line 46
    .line 47
    int-to-long v3, v3

    .line 48
    invoke-virtual {v0, v3, v4}, Lu01/a0;->N(J)Lu01/g;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v0, v1}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 52
    .line 53
    .line 54
    const/4 v3, 0x2

    .line 55
    int-to-long v3, v3

    .line 56
    invoke-virtual {v0, v3, v4}, Lu01/a0;->N(J)Lu01/g;

    .line 57
    .line 58
    .line 59
    invoke-virtual {v0, v1}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 60
    .line 61
    .line 62
    invoke-virtual {v0, v1}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 63
    .line 64
    .line 65
    iget-object v3, p0, Lf01/g;->l:Ljava/util/LinkedHashMap;

    .line 66
    .line 67
    invoke-virtual {v3}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 68
    .line 69
    .line 70
    move-result-object v3

    .line 71
    invoke-interface {v3}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 76
    .line 77
    .line 78
    move-result v4

    .line 79
    if-eqz v4, :cond_3

    .line 80
    .line 81
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    const-string v5, "next(...)"

    .line 86
    .line 87
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    check-cast v4, Lf01/c;

    .line 91
    .line 92
    iget-object v5, v4, Lf01/c;->g:La8/b;

    .line 93
    .line 94
    const/16 v6, 0x20

    .line 95
    .line 96
    if-eqz v5, :cond_1

    .line 97
    .line 98
    sget-object v5, Lf01/g;->y:Ljava/lang/String;

    .line 99
    .line 100
    invoke-virtual {v0, v5}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 101
    .line 102
    .line 103
    invoke-virtual {v0, v6}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 104
    .line 105
    .line 106
    iget-object v4, v4, Lf01/c;->a:Ljava/lang/String;

    .line 107
    .line 108
    invoke-virtual {v0, v4}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 109
    .line 110
    .line 111
    invoke-virtual {v0, v1}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 112
    .line 113
    .line 114
    goto :goto_1

    .line 115
    :catchall_1
    move-exception v1

    .line 116
    goto :goto_3

    .line 117
    :cond_1
    sget-object v5, Lf01/g;->x:Ljava/lang/String;

    .line 118
    .line 119
    invoke-virtual {v0, v5}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 120
    .line 121
    .line 122
    invoke-virtual {v0, v6}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 123
    .line 124
    .line 125
    iget-object v5, v4, Lf01/c;->a:Ljava/lang/String;

    .line 126
    .line 127
    invoke-virtual {v0, v5}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 128
    .line 129
    .line 130
    iget-object v4, v4, Lf01/c;->b:[J

    .line 131
    .line 132
    array-length v5, v4

    .line 133
    move v7, v2

    .line 134
    :goto_2
    if-ge v7, v5, :cond_2

    .line 135
    .line 136
    aget-wide v8, v4, v7

    .line 137
    .line 138
    invoke-virtual {v0, v6}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 139
    .line 140
    .line 141
    invoke-virtual {v0, v8, v9}, Lu01/a0;->N(J)Lu01/g;

    .line 142
    .line 143
    .line 144
    add-int/lit8 v7, v7, 0x1

    .line 145
    .line 146
    goto :goto_2

    .line 147
    :cond_2
    invoke-virtual {v0, v1}, Lu01/a0;->writeByte(I)Lu01/g;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 148
    .line 149
    .line 150
    goto :goto_1

    .line 151
    :cond_3
    :try_start_2
    invoke-virtual {v0}, Lu01/a0;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 152
    .line 153
    .line 154
    const/4 v0, 0x0

    .line 155
    goto :goto_5

    .line 156
    :catchall_2
    move-exception v0

    .line 157
    goto :goto_5

    .line 158
    :goto_3
    :try_start_3
    invoke-virtual {v0}, Lu01/a0;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 159
    .line 160
    .line 161
    goto :goto_4

    .line 162
    :catchall_3
    move-exception v0

    .line 163
    :try_start_4
    invoke-static {v1, v0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 164
    .line 165
    .line 166
    :goto_4
    move-object v0, v1

    .line 167
    :goto_5
    if-nez v0, :cond_6

    .line 168
    .line 169
    iget-object v0, p0, Lf01/g;->e:Lf01/f;

    .line 170
    .line 171
    iget-object v1, p0, Lf01/g;->g:Lu01/y;

    .line 172
    .line 173
    invoke-virtual {v0, v1}, Lu01/k;->j(Lu01/y;)Z

    .line 174
    .line 175
    .line 176
    move-result v0

    .line 177
    if-eqz v0, :cond_4

    .line 178
    .line 179
    iget-object v0, p0, Lf01/g;->e:Lf01/f;

    .line 180
    .line 181
    iget-object v1, p0, Lf01/g;->g:Lu01/y;

    .line 182
    .line 183
    iget-object v3, p0, Lf01/g;->i:Lu01/y;

    .line 184
    .line 185
    invoke-virtual {v0, v1, v3}, Lu01/l;->b(Lu01/y;Lu01/y;)V

    .line 186
    .line 187
    .line 188
    iget-object v0, p0, Lf01/g;->e:Lf01/f;

    .line 189
    .line 190
    iget-object v1, p0, Lf01/g;->h:Lu01/y;

    .line 191
    .line 192
    iget-object v3, p0, Lf01/g;->g:Lu01/y;

    .line 193
    .line 194
    invoke-virtual {v0, v1, v3}, Lu01/l;->b(Lu01/y;Lu01/y;)V

    .line 195
    .line 196
    .line 197
    iget-object v0, p0, Lf01/g;->e:Lf01/f;

    .line 198
    .line 199
    iget-object v1, p0, Lf01/g;->i:Lu01/y;

    .line 200
    .line 201
    invoke-static {v0, v1}, Le01/e;->d(Lf01/f;Lu01/y;)V

    .line 202
    .line 203
    .line 204
    goto :goto_6

    .line 205
    :cond_4
    iget-object v0, p0, Lf01/g;->e:Lf01/f;

    .line 206
    .line 207
    iget-object v1, p0, Lf01/g;->h:Lu01/y;

    .line 208
    .line 209
    iget-object v3, p0, Lf01/g;->g:Lu01/y;

    .line 210
    .line 211
    invoke-virtual {v0, v1, v3}, Lu01/l;->b(Lu01/y;Lu01/y;)V

    .line 212
    .line 213
    .line 214
    :goto_6
    iget-object v0, p0, Lf01/g;->k:Lu01/a0;

    .line 215
    .line 216
    if-eqz v0, :cond_5

    .line 217
    .line 218
    invoke-static {v0}, Le01/e;->b(Ljava/io/Closeable;)V

    .line 219
    .line 220
    .line 221
    :cond_5
    iget-object v0, p0, Lf01/g;->e:Lf01/f;

    .line 222
    .line 223
    iget-object v1, p0, Lf01/g;->g:Lu01/y;

    .line 224
    .line 225
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 226
    .line 227
    .line 228
    const-string v3, "file"

    .line 229
    .line 230
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 231
    .line 232
    .line 233
    invoke-virtual {v0, v1}, Lu01/l;->a(Lu01/y;)Lu01/f0;

    .line 234
    .line 235
    .line 236
    move-result-object v0

    .line 237
    new-instance v1, Lf01/h;

    .line 238
    .line 239
    new-instance v3, Le81/w;

    .line 240
    .line 241
    const/4 v4, 0x4

    .line 242
    invoke-direct {v3, p0, v4}, Le81/w;-><init>(Ljava/lang/Object;I)V

    .line 243
    .line 244
    .line 245
    invoke-direct {v1, v0, v3}, Lf01/h;-><init>(Lu01/f0;Lay0/k;)V

    .line 246
    .line 247
    .line 248
    invoke-static {v1}, Lu01/b;->b(Lu01/f0;)Lu01/a0;

    .line 249
    .line 250
    .line 251
    move-result-object v0

    .line 252
    iput-object v0, p0, Lf01/g;->k:Lu01/a0;

    .line 253
    .line 254
    iput-boolean v2, p0, Lf01/g;->n:Z

    .line 255
    .line 256
    iput-boolean v2, p0, Lf01/g;->s:Z
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 257
    .line 258
    monitor-exit p0

    .line 259
    return-void

    .line 260
    :cond_6
    :try_start_5
    throw v0

    .line 261
    :goto_7
    monitor-exit p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 262
    throw v0
.end method
