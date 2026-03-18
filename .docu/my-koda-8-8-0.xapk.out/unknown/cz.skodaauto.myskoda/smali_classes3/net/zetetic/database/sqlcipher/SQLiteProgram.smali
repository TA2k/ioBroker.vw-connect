.class public abstract Lnet/zetetic/database/sqlcipher/SQLiteProgram;
.super Lnet/zetetic/database/sqlcipher/SQLiteClosable;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lva/a;


# static fields
.field private static final EMPTY_STRING_ARRAY:[Ljava/lang/String;


# instance fields
.field private final mBindArgs:[Ljava/lang/Object;

.field private final mColumnNames:[Ljava/lang/String;

.field private final mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

.field private final mNumParameters:I

.field private final mReadOnly:Z

.field private final mSql:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Ljava/lang/String;

    .line 3
    .line 4
    sput-object v0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->EMPTY_STRING_ARRAY:[Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public constructor <init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p2

    .line 10
    iput-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mSql:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {p2}, Landroid/database/DatabaseUtils;->getSqlStatementType(Ljava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const/4 v1, 0x4

    .line 17
    const/4 v2, 0x0

    .line 18
    if-eq v0, v1, :cond_1

    .line 19
    .line 20
    const/4 v1, 0x5

    .line 21
    if-eq v0, v1, :cond_1

    .line 22
    .line 23
    const/4 v1, 0x6

    .line 24
    if-eq v0, v1, :cond_1

    .line 25
    .line 26
    const/4 v1, 0x1

    .line 27
    if-ne v0, v1, :cond_0

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    move v1, v2

    .line 31
    :goto_0
    new-instance v0, Lnet/zetetic/database/sqlcipher/SQLiteStatementInfo;

    .line 32
    .line 33
    invoke-direct {v0}, Lnet/zetetic/database/sqlcipher/SQLiteStatementInfo;-><init>()V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getThreadSession()Lnet/zetetic/database/sqlcipher/SQLiteSession;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    invoke-virtual {p1, v1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getThreadDefaultConnectionFlags(Z)I

    .line 41
    .line 42
    .line 43
    move-result p1

    .line 44
    invoke-virtual {v3, p2, p1, p4, v0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->prepare(Ljava/lang/String;ILandroid/os/CancellationSignal;Lnet/zetetic/database/sqlcipher/SQLiteStatementInfo;)V

    .line 45
    .line 46
    .line 47
    iget-boolean p1, v0, Lnet/zetetic/database/sqlcipher/SQLiteStatementInfo;->readOnly:Z

    .line 48
    .line 49
    iput-boolean p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mReadOnly:Z

    .line 50
    .line 51
    iget-object p1, v0, Lnet/zetetic/database/sqlcipher/SQLiteStatementInfo;->columnNames:[Ljava/lang/String;

    .line 52
    .line 53
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mColumnNames:[Ljava/lang/String;

    .line 54
    .line 55
    iget p1, v0, Lnet/zetetic/database/sqlcipher/SQLiteStatementInfo;->numParameters:I

    .line 56
    .line 57
    iput p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mNumParameters:I

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_1
    iput-boolean v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mReadOnly:Z

    .line 61
    .line 62
    sget-object p1, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->EMPTY_STRING_ARRAY:[Ljava/lang/String;

    .line 63
    .line 64
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mColumnNames:[Ljava/lang/String;

    .line 65
    .line 66
    iput v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mNumParameters:I

    .line 67
    .line 68
    :goto_1
    if-eqz p3, :cond_3

    .line 69
    .line 70
    array-length p1, p3

    .line 71
    iget p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mNumParameters:I

    .line 72
    .line 73
    if-gt p1, p2, :cond_2

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_2
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 77
    .line 78
    new-instance p2, Ljava/lang/StringBuilder;

    .line 79
    .line 80
    const-string p4, "Too many bind arguments.  "

    .line 81
    .line 82
    invoke-direct {p2, p4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    array-length p3, p3

    .line 86
    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    const-string p3, " arguments were provided but the statement needs "

    .line 90
    .line 91
    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    iget p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mNumParameters:I

    .line 95
    .line 96
    const-string p3, " arguments."

    .line 97
    .line 98
    invoke-static {p0, p3, p2}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    throw p1

    .line 106
    :cond_3
    :goto_2
    iget p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mNumParameters:I

    .line 107
    .line 108
    if-eqz p1, :cond_5

    .line 109
    .line 110
    new-array p1, p1, [Ljava/lang/Object;

    .line 111
    .line 112
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mBindArgs:[Ljava/lang/Object;

    .line 113
    .line 114
    if-eqz p3, :cond_4

    .line 115
    .line 116
    array-length p0, p3

    .line 117
    invoke-static {p3, v2, p1, v2, p0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 118
    .line 119
    .line 120
    :cond_4
    return-void

    .line 121
    :cond_5
    const/4 p1, 0x0

    .line 122
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mBindArgs:[Ljava/lang/Object;

    .line 123
    .line 124
    return-void
.end method

.method private bind(ILjava/lang/Object;)V
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    if-lt p1, v0, :cond_0

    .line 3
    .line 4
    iget v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mNumParameters:I

    .line 5
    .line 6
    if-gt p1, v1, :cond_0

    .line 7
    .line 8
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mBindArgs:[Ljava/lang/Object;

    .line 9
    .line 10
    sub-int/2addr p1, v0

    .line 11
    aput-object p2, p0, p1

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    new-instance p2, Ljava/lang/IllegalArgumentException;

    .line 15
    .line 16
    const-string v0, "Cannot bind argument at index "

    .line 17
    .line 18
    const-string v1, " because the index is out of range.  The statement has "

    .line 19
    .line 20
    invoke-static {v0, p1, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    iget p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mNumParameters:I

    .line 25
    .line 26
    const-string v0, " parameters."

    .line 27
    .line 28
    invoke-static {p0, v0, p1}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-direct {p2, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    throw p2
.end method


# virtual methods
.method public varargs bindAllArgs([Ljava/lang/Object;)V
    .locals 2

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    array-length v0, p1

    .line 4
    :goto_0
    if-eqz v0, :cond_0

    .line 5
    .line 6
    add-int/lit8 v1, v0, -0x1

    .line 7
    .line 8
    aget-object v1, p1, v1

    .line 9
    .line 10
    invoke-direct {p0, v0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->bind(ILjava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    add-int/lit8 v0, v0, -0x1

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    return-void
.end method

.method public bindAllArgsAsStrings([Ljava/lang/String;)V
    .locals 2

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    array-length v0, p1

    .line 4
    :goto_0
    if-eqz v0, :cond_0

    .line 5
    .line 6
    add-int/lit8 v1, v0, -0x1

    .line 7
    .line 8
    aget-object v1, p1, v1

    .line 9
    .line 10
    invoke-virtual {p0, v0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->bindString(ILjava/lang/String;)V

    .line 11
    .line 12
    .line 13
    add-int/lit8 v0, v0, -0x1

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    return-void
.end method

.method public bindBlob(I[B)V
    .locals 1

    .line 1
    if-eqz p2, :cond_0

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->bind(ILjava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 8
    .line 9
    const-string p2, "the bind value at index "

    .line 10
    .line 11
    const-string v0, " is null"

    .line 12
    .line 13
    invoke-static {p2, p1, v0}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public bindDouble(ID)V
    .locals 0

    .line 1
    invoke-static {p2, p3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    invoke-direct {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->bind(ILjava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public bindLong(IJ)V
    .locals 0

    .line 1
    invoke-static {p2, p3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    invoke-direct {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->bind(ILjava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public bindNull(I)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, v0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->bind(ILjava/lang/Object;)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public bindString(ILjava/lang/String;)V
    .locals 1

    .line 1
    if-eqz p2, :cond_0

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->bind(ILjava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 8
    .line 9
    const-string p2, "the bind value at index "

    .line 10
    .line 11
    const-string v0, " is null"

    .line 12
    .line 13
    invoke-static {p2, p1, v0}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public clearBindings()V
    .locals 1

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mBindArgs:[Ljava/lang/Object;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-static {p0, v0}, Ljava/util/Arrays;->fill([Ljava/lang/Object;Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    :cond_0
    return-void
.end method

.method public final getBindArgs()[Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mBindArgs:[Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getColumnNames()[Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mColumnNames:[Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getConnectionFlags()I
    .locals 1

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 2
    .line 3
    iget-boolean p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mReadOnly:Z

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getThreadDefaultConnectionFlags(Z)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final getDatabase()Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSession()Lnet/zetetic/database/sqlcipher/SQLiteSession;
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 2
    .line 3
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getThreadSession()Lnet/zetetic/database/sqlcipher/SQLiteSession;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getSql()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mSql:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getUniqueId()I
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    const/4 p0, -0x1

    .line 2
    return p0
.end method

.method public onAllReferencesReleased()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->clearBindings()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final onCorruption(Landroid/database/sqlite/SQLiteException;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->onCorruption(Landroid/database/sqlite/SQLiteException;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
