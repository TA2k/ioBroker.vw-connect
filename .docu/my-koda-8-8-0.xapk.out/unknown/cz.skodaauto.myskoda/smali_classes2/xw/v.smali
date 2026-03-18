.class public final Lxw/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Ljava/lang/String;

.field public static final e:Ljava/lang/String;

.field public static final f:Ljava/lang/String;

.field public static final g:Ljava/lang/String;

.field public static final h:Ljava/lang/String;

.field public static final i:Ljava/lang/String;

.field public static final j:Lxw/c;


# instance fields
.field public final a:[Lxw/u;

.field public final b:Lxw/h;

.field public final c:Ljava/util/concurrent/ConcurrentHashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/String;

    .line 2
    .line 3
    const-string v1, "<no fetcher found>"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/String;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lxw/v;->d:Ljava/lang/String;

    .line 9
    .line 10
    const-string v0, "."

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/String;->intern()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    sput-object v0, Lxw/v;->e:Ljava/lang/String;

    .line 17
    .line 18
    const-string v0, "this"

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/String;->intern()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    sput-object v0, Lxw/v;->f:Ljava/lang/String;

    .line 25
    .line 26
    const-string v0, "-first"

    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/String;->intern()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    sput-object v0, Lxw/v;->g:Ljava/lang/String;

    .line 33
    .line 34
    const-string v0, "-last"

    .line 35
    .line 36
    invoke-virtual {v0}, Ljava/lang/String;->intern()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    sput-object v0, Lxw/v;->h:Ljava/lang/String;

    .line 41
    .line 42
    const-string v0, "-index"

    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/lang/String;->intern()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    sput-object v0, Lxw/v;->i:Ljava/lang/String;

    .line 49
    .line 50
    new-instance v0, Lxw/c;

    .line 51
    .line 52
    const/4 v1, 0x4

    .line 53
    invoke-direct {v0, v1}, Lxw/c;-><init>(I)V

    .line 54
    .line 55
    .line 56
    sput-object v0, Lxw/v;->j:Lxw/c;

    .line 57
    .line 58
    return-void
.end method

.method public constructor <init>([Lxw/u;Lxw/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxw/v;->a:[Lxw/u;

    .line 5
    .line 6
    iput-object p2, p0, Lxw/v;->b:Lxw/h;

    .line 7
    .line 8
    new-instance p1, Ljava/util/concurrent/ConcurrentHashMap;

    .line 9
    .line 10
    invoke-direct {p1}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lxw/v;->c:Ljava/util/concurrent/ConcurrentHashMap;

    .line 14
    .line 15
    return-void
.end method

.method public static a(Ljava/lang/String;IZLjava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Lxw/v;->d:Ljava/lang/String;

    .line 2
    .line 3
    if-ne p3, v0, :cond_1

    .line 4
    .line 5
    if-eqz p2, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return-object p0

    .line 9
    :cond_0
    new-instance p2, Lxw/r;

    .line 10
    .line 11
    new-instance p3, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v0, "No method or field with name \'"

    .line 14
    .line 15
    invoke-direct {p3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string p0, "\' on line "

    .line 22
    .line 23
    invoke-virtual {p3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-direct {p2, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p2

    .line 37
    :cond_1
    return-object p3
.end method


# virtual methods
.method public final b(Lxw/s;Ljava/lang/String;IZ)Ljava/lang/Object;
    .locals 5

    .line 1
    sget-object v0, Lxw/v;->g:Ljava/lang/String;

    .line 2
    .line 3
    if-ne p2, v0, :cond_0

    .line 4
    .line 5
    iget-boolean p0, p1, Lxw/s;->d:Z

    .line 6
    .line 7
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object v0, Lxw/v;->h:Ljava/lang/String;

    .line 13
    .line 14
    if-ne p2, v0, :cond_1

    .line 15
    .line 16
    iget-boolean p0, p1, Lxw/s;->e:Z

    .line 17
    .line 18
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :cond_1
    sget-object v0, Lxw/v;->i:Ljava/lang/String;

    .line 24
    .line 25
    if-ne p2, v0, :cond_2

    .line 26
    .line 27
    iget p0, p1, Lxw/s;->c:I

    .line 28
    .line 29
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :cond_2
    move-object v0, p1

    .line 35
    :goto_0
    sget-object v1, Lxw/v;->d:Ljava/lang/String;

    .line 36
    .line 37
    if-eqz v0, :cond_4

    .line 38
    .line 39
    iget-object v2, v0, Lxw/s;->a:Ljava/lang/Object;

    .line 40
    .line 41
    invoke-virtual {p0, p2, p3, v2}, Lxw/v;->c(Ljava/lang/String;ILjava/lang/Object;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    if-eq v2, v1, :cond_3

    .line 46
    .line 47
    return-object v2

    .line 48
    :cond_3
    iget-object v0, v0, Lxw/s;->b:Lxw/s;

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_4
    sget-object v0, Lxw/v;->e:Ljava/lang/String;

    .line 52
    .line 53
    if-eq p2, v0, :cond_9

    .line 54
    .line 55
    invoke-virtual {p2, v0}, Ljava/lang/String;->indexOf(Ljava/lang/String;)I

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    const/4 v2, -0x1

    .line 60
    if-eq v0, v2, :cond_9

    .line 61
    .line 62
    const-string v0, "\\."

    .line 63
    .line 64
    invoke-virtual {p2, v0}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    const/4 v2, 0x0

    .line 69
    aget-object v2, v0, v2

    .line 70
    .line 71
    invoke-virtual {v2}, Ljava/lang/String;->intern()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    invoke-virtual {p0, p1, v2, p3, p4}, Lxw/v;->b(Lxw/s;Ljava/lang/String;IZ)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    const/4 v2, 0x1

    .line 80
    move v3, v2

    .line 81
    :goto_1
    array-length v4, v0

    .line 82
    if-ge v3, v4, :cond_8

    .line 83
    .line 84
    if-ne p1, v1, :cond_6

    .line 85
    .line 86
    if-eqz p4, :cond_5

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_5
    new-instance p0, Lxw/r;

    .line 90
    .line 91
    const-string p1, "\' on line "

    .line 92
    .line 93
    const-string p4, ". \'"

    .line 94
    .line 95
    const-string v1, "Missing context for compound variable \'"

    .line 96
    .line 97
    invoke-static {v1, p3, p2, p1, p4}, La7/g0;->m(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    sub-int/2addr v3, v2

    .line 102
    aget-object p2, v0, v3

    .line 103
    .line 104
    const-string p3, "\' was not found."

    .line 105
    .line 106
    invoke-static {p1, p2, p3}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    throw p0

    .line 114
    :cond_6
    if-nez p1, :cond_7

    .line 115
    .line 116
    :goto_2
    const/4 p0, 0x0

    .line 117
    return-object p0

    .line 118
    :cond_7
    aget-object v4, v0, v3

    .line 119
    .line 120
    invoke-virtual {v4}, Ljava/lang/String;->intern()Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v4

    .line 124
    invoke-virtual {p0, v4, p3, p1}, Lxw/v;->c(Ljava/lang/String;ILjava/lang/Object;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    add-int/lit8 v3, v3, 0x1

    .line 129
    .line 130
    goto :goto_1

    .line 131
    :cond_8
    invoke-static {p2, p3, p4, p1}, Lxw/v;->a(Ljava/lang/String;IZLjava/lang/Object;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    return-object p0

    .line 136
    :cond_9
    invoke-static {p2, p3, p4, v1}, Lxw/v;->a(Ljava/lang/String;IZLjava/lang/Object;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    return-object p0
.end method

.method public final c(Ljava/lang/String;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lxw/v;->b:Lxw/h;

    .line 2
    .line 3
    iget-object v0, v0, Lxw/h;->a:Lxw/e;

    .line 4
    .line 5
    const-string v1, "\' on line "

    .line 6
    .line 7
    if-eqz p3, :cond_2

    .line 8
    .line 9
    new-instance v2, Lxw/t;

    .line 10
    .line 11
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    move-result-object v3

    .line 15
    invoke-direct {v2, v3, p1}, Lxw/t;-><init>(Ljava/lang/Class;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lxw/v;->c:Ljava/util/concurrent/ConcurrentHashMap;

    .line 19
    .line 20
    invoke-virtual {p0, v2}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    check-cast v3, Lxw/p;

    .line 25
    .line 26
    if-eqz v3, :cond_0

    .line 27
    .line 28
    :try_start_0
    invoke-interface {v3, p3, p1}, Lxw/p;->get(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 32
    return-object p0

    .line 33
    :catch_0
    iget-object v3, v2, Lxw/t;->b:Ljava/lang/String;

    .line 34
    .line 35
    invoke-virtual {v0, p3, v3}, Lxw/e;->d(Ljava/lang/Object;Ljava/lang/String;)Lxw/p;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    goto :goto_0

    .line 40
    :cond_0
    invoke-virtual {v0, p3, p1}, Lxw/e;->d(Ljava/lang/Object;Ljava/lang/String;)Lxw/p;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    :goto_0
    if-nez v0, :cond_1

    .line 45
    .line 46
    sget-object v0, Lxw/v;->j:Lxw/c;

    .line 47
    .line 48
    :cond_1
    :try_start_1
    invoke-interface {v0, p3, p1}, Lxw/p;->get(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p3

    .line 52
    invoke-virtual {p0, v2, v0}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 53
    .line 54
    .line 55
    return-object p3

    .line 56
    :catch_1
    move-exception p0

    .line 57
    new-instance p3, Lxw/r;

    .line 58
    .line 59
    new-instance v0, Ljava/lang/StringBuilder;

    .line 60
    .line 61
    const-string v2, "Failure fetching variable \'"

    .line 62
    .line 63
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    invoke-direct {p3, p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 80
    .line 81
    .line 82
    throw p3

    .line 83
    :cond_2
    new-instance p0, Ljava/lang/NullPointerException;

    .line 84
    .line 85
    new-instance p3, Ljava/lang/StringBuilder;

    .line 86
    .line 87
    const-string v0, "Null context for variable \'"

    .line 88
    .line 89
    invoke-direct {p3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    invoke-virtual {p3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    throw p0
.end method
