.class public final Lwa/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/sqlite/db/SupportSQLiteDatabase;


# static fields
.field public static final e:[Ljava/lang/String;

.field public static final f:[Ljava/lang/String;

.field public static final g:Ljava/lang/Object;

.field public static final h:Ljava/lang/Object;


# instance fields
.field public final d:Landroid/database/sqlite/SQLiteDatabase;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    const-string v4, " OR IGNORE "

    .line 2
    .line 3
    const-string v5, " OR REPLACE "

    .line 4
    .line 5
    const-string v0, ""

    .line 6
    .line 7
    const-string v1, " OR ROLLBACK "

    .line 8
    .line 9
    const-string v2, " OR ABORT "

    .line 10
    .line 11
    const-string v3, " OR FAIL "

    .line 12
    .line 13
    filled-new-array/range {v0 .. v5}, [Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sput-object v0, Lwa/b;->e:[Ljava/lang/String;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    new-array v0, v0, [Ljava/lang/String;

    .line 21
    .line 22
    sput-object v0, Lwa/b;->f:[Ljava/lang/String;

    .line 23
    .line 24
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 25
    .line 26
    new-instance v1, Lvd/i;

    .line 27
    .line 28
    const/16 v2, 0x13

    .line 29
    .line 30
    invoke-direct {v1, v2}, Lvd/i;-><init>(I)V

    .line 31
    .line 32
    .line 33
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    sput-object v1, Lwa/b;->g:Ljava/lang/Object;

    .line 38
    .line 39
    new-instance v1, Lvd/i;

    .line 40
    .line 41
    const/16 v2, 0x14

    .line 42
    .line 43
    invoke-direct {v1, v2}, Lvd/i;-><init>(I)V

    .line 44
    .line 45
    .line 46
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    sput-object v0, Lwa/b;->h:Ljava/lang/Object;

    .line 51
    .line 52
    return-void
.end method

.method public constructor <init>(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwa/b;->d:Landroid/database/sqlite/SQLiteDatabase;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final beginTransaction()V
    .locals 0

    .line 1
    iget-object p0, p0, Lwa/b;->d:Landroid/database/sqlite/SQLiteDatabase;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final beginTransactionNonExclusive()V
    .locals 0

    .line 1
    iget-object p0, p0, Lwa/b;->d:Landroid/database/sqlite/SQLiteDatabase;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->beginTransactionNonExclusive()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final beginTransactionReadOnly()V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    sget-object v1, Lwa/b;->h:Ljava/lang/Object;

    .line 7
    .line 8
    invoke-interface {v1}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    check-cast v2, Ljava/lang/reflect/Method;

    .line 13
    .line 14
    if-eqz v2, :cond_1

    .line 15
    .line 16
    sget-object v2, Lwa/b;->g:Ljava/lang/Object;

    .line 17
    .line 18
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    check-cast v3, Ljava/lang/reflect/Method;

    .line 23
    .line 24
    if-eqz v3, :cond_1

    .line 25
    .line 26
    invoke-interface {v1}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    check-cast v1, Ljava/lang/reflect/Method;

    .line 31
    .line 32
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    check-cast v2, Ljava/lang/reflect/Method;

    .line 40
    .line 41
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    iget-object p0, p0, Lwa/b;->d:Landroid/database/sqlite/SQLiteDatabase;

    .line 45
    .line 46
    const/4 v3, 0x0

    .line 47
    invoke-virtual {v2, p0, v3}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    if-eqz p0, :cond_0

    .line 52
    .line 53
    filled-new-array {v0, v3, v0, v3}, [Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    invoke-virtual {v1, p0, v0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    return-void

    .line 61
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 62
    .line 63
    const-string v0, "Required value was null."

    .line 64
    .line 65
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p0

    .line 69
    :cond_1
    invoke-virtual {p0}, Lwa/b;->beginTransaction()V

    .line 70
    .line 71
    .line 72
    return-void
.end method

.method public final beginTransactionWithListener(Landroid/database/sqlite/SQLiteTransactionListener;)V
    .locals 0

    const/4 p0, 0x0

    throw p0
.end method

.method public final close()V
    .locals 0

    .line 1
    iget-object p0, p0, Lwa/b;->d:Landroid/database/sqlite/SQLiteDatabase;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteClosable;->close()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final compileStatement(Ljava/lang/String;)Landroidx/sqlite/db/SupportSQLiteStatement;
    .locals 1

    .line 1
    const-string v0, "sql"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lwa/j;

    .line 7
    .line 8
    iget-object p0, p0, Lwa/b;->d:Landroid/database/sqlite/SQLiteDatabase;

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const-string p1, "compileStatement(...)"

    .line 15
    .line 16
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-direct {v0, p0}, Lwa/j;-><init>(Landroid/database/sqlite/SQLiteStatement;)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public final disableWriteAheadLogging()V
    .locals 0

    .line 1
    iget-object p0, p0, Lwa/b;->d:Landroid/database/sqlite/SQLiteDatabase;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->disableWriteAheadLogging()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final enableWriteAheadLogging()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lwa/b;->d:Landroid/database/sqlite/SQLiteDatabase;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->enableWriteAheadLogging()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final endTransaction()V
    .locals 0

    .line 1
    iget-object p0, p0, Lwa/b;->d:Landroid/database/sqlite/SQLiteDatabase;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final execSQL(Ljava/lang/String;)V
    .locals 1

    const-string v0, "sql"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    iget-object p0, p0, Lwa/b;->d:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {p0, p1}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    return-void
.end method

.method public final execSQL(Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    const-string p1, "INSERT OR REPLACE INTO `Preference` (`key`, `long_value`) VALUES (@key, @long_value)"

    .line 2
    iget-object p0, p0, Lwa/b;->d:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {p0, p1, p2}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public final inTransaction()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lwa/b;->d:Landroid/database/sqlite/SQLiteDatabase;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->inTransaction()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final isOpen()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lwa/b;->d:Landroid/database/sqlite/SQLiteDatabase;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->isOpen()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final isWriteAheadLoggingEnabled()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lwa/b;->d:Landroid/database/sqlite/SQLiteDatabase;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->isWriteAheadLoggingEnabled()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final query(Landroidx/sqlite/db/SupportSQLiteQuery;)Landroid/database/Cursor;
    .locals 3

    .line 1
    new-instance v0, Lge/a;

    .line 2
    .line 3
    const/4 v1, 0x7

    .line 4
    invoke-direct {v0, p1, v1}, Lge/a;-><init>(Ljava/lang/Object;I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Lwa/a;

    .line 8
    .line 9
    invoke-direct {v1, v0}, Lwa/a;-><init>(Lge/a;)V

    .line 10
    .line 11
    .line 12
    invoke-interface {p1}, Landroidx/sqlite/db/SupportSQLiteQuery;->c()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    sget-object v0, Lwa/b;->f:[Ljava/lang/String;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    iget-object p0, p0, Lwa/b;->d:Landroid/database/sqlite/SQLiteDatabase;

    .line 20
    .line 21
    invoke-virtual {p0, v1, p1, v0, v2}, Landroid/database/sqlite/SQLiteDatabase;->rawQueryWithFactory(Landroid/database/sqlite/SQLiteDatabase$CursorFactory;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    const-string p1, "rawQueryWithFactory(...)"

    .line 26
    .line 27
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    return-object p0
.end method

.method public final setTransactionSuccessful()V
    .locals 0

    .line 1
    iget-object p0, p0, Lwa/b;->d:Landroid/database/sqlite/SQLiteDatabase;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final update(Ljava/lang/String;ILandroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/Object;)I
    .locals 5

    .line 1
    invoke-virtual {p3}, Landroid/content/ContentValues;->size()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-eqz p1, :cond_10

    .line 6
    .line 7
    invoke-virtual {p3}, Landroid/content/ContentValues;->size()I

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    array-length p2, p5

    .line 12
    add-int/2addr p2, p1

    .line 13
    new-array p4, p2, [Ljava/lang/Object;

    .line 14
    .line 15
    new-instance v0, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    const-string v1, "UPDATE "

    .line 18
    .line 19
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    sget-object v1, Lwa/b;->e:[Ljava/lang/String;

    .line 23
    .line 24
    const/4 v2, 0x3

    .line 25
    aget-object v1, v1, v2

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, "WorkSpec SET "

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {p3}, Landroid/content/ContentValues;->keySet()Ljava/util/Set;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    const/4 v2, 0x0

    .line 44
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 45
    .line 46
    .line 47
    move-result v3

    .line 48
    if-eqz v3, :cond_1

    .line 49
    .line 50
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v3

    .line 54
    check-cast v3, Ljava/lang/String;

    .line 55
    .line 56
    if-lez v2, :cond_0

    .line 57
    .line 58
    const-string v4, ","

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_0
    const-string v4, ""

    .line 62
    .line 63
    :goto_1
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    add-int/lit8 v4, v2, 0x1

    .line 70
    .line 71
    invoke-virtual {p3, v3}, Landroid/content/ContentValues;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    aput-object v3, p4, v2

    .line 76
    .line 77
    const-string v2, "=?"

    .line 78
    .line 79
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    move v2, v4

    .line 83
    goto :goto_0

    .line 84
    :cond_1
    move p3, p1

    .line 85
    :goto_2
    if-ge p3, p2, :cond_2

    .line 86
    .line 87
    sub-int v1, p3, p1

    .line 88
    .line 89
    aget-object v1, p5, v1

    .line 90
    .line 91
    aput-object v1, p4, p3

    .line 92
    .line 93
    add-int/lit8 p3, p3, 0x1

    .line 94
    .line 95
    goto :goto_2

    .line 96
    :cond_2
    const-string p1, "last_enqueue_time = 0 AND interval_duration <> 0 "

    .line 97
    .line 98
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 99
    .line 100
    .line 101
    move-result p1

    .line 102
    if-nez p1, :cond_3

    .line 103
    .line 104
    const-string p1, " WHERE last_enqueue_time = 0 AND interval_duration <> 0 "

    .line 105
    .line 106
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    :cond_3
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    invoke-virtual {p0, p1}, Lwa/b;->compileStatement(Ljava/lang/String;)Landroidx/sqlite/db/SupportSQLiteStatement;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    array-length p1, p4

    .line 118
    const/4 p2, 0x0

    .line 119
    :goto_3
    if-ge p2, p1, :cond_f

    .line 120
    .line 121
    aget-object p3, p4, p2

    .line 122
    .line 123
    add-int/lit8 p2, p2, 0x1

    .line 124
    .line 125
    if-nez p3, :cond_4

    .line 126
    .line 127
    invoke-interface {p0, p2}, Lva/a;->bindNull(I)V

    .line 128
    .line 129
    .line 130
    goto :goto_3

    .line 131
    :cond_4
    instance-of p5, p3, [B

    .line 132
    .line 133
    if-eqz p5, :cond_5

    .line 134
    .line 135
    check-cast p3, [B

    .line 136
    .line 137
    invoke-interface {p0, p2, p3}, Lva/a;->bindBlob(I[B)V

    .line 138
    .line 139
    .line 140
    goto :goto_3

    .line 141
    :cond_5
    instance-of p5, p3, Ljava/lang/Float;

    .line 142
    .line 143
    if-eqz p5, :cond_6

    .line 144
    .line 145
    check-cast p3, Ljava/lang/Number;

    .line 146
    .line 147
    invoke-virtual {p3}, Ljava/lang/Number;->floatValue()F

    .line 148
    .line 149
    .line 150
    move-result p3

    .line 151
    float-to-double v0, p3

    .line 152
    invoke-interface {p0, p2, v0, v1}, Lva/a;->bindDouble(ID)V

    .line 153
    .line 154
    .line 155
    goto :goto_3

    .line 156
    :cond_6
    instance-of p5, p3, Ljava/lang/Double;

    .line 157
    .line 158
    if-eqz p5, :cond_7

    .line 159
    .line 160
    check-cast p3, Ljava/lang/Number;

    .line 161
    .line 162
    invoke-virtual {p3}, Ljava/lang/Number;->doubleValue()D

    .line 163
    .line 164
    .line 165
    move-result-wide v0

    .line 166
    invoke-interface {p0, p2, v0, v1}, Lva/a;->bindDouble(ID)V

    .line 167
    .line 168
    .line 169
    goto :goto_3

    .line 170
    :cond_7
    instance-of p5, p3, Ljava/lang/Long;

    .line 171
    .line 172
    if-eqz p5, :cond_8

    .line 173
    .line 174
    check-cast p3, Ljava/lang/Number;

    .line 175
    .line 176
    invoke-virtual {p3}, Ljava/lang/Number;->longValue()J

    .line 177
    .line 178
    .line 179
    move-result-wide v0

    .line 180
    invoke-interface {p0, p2, v0, v1}, Lva/a;->bindLong(IJ)V

    .line 181
    .line 182
    .line 183
    goto :goto_3

    .line 184
    :cond_8
    instance-of p5, p3, Ljava/lang/Integer;

    .line 185
    .line 186
    if-eqz p5, :cond_9

    .line 187
    .line 188
    check-cast p3, Ljava/lang/Number;

    .line 189
    .line 190
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 191
    .line 192
    .line 193
    move-result p3

    .line 194
    int-to-long v0, p3

    .line 195
    invoke-interface {p0, p2, v0, v1}, Lva/a;->bindLong(IJ)V

    .line 196
    .line 197
    .line 198
    goto :goto_3

    .line 199
    :cond_9
    instance-of p5, p3, Ljava/lang/Short;

    .line 200
    .line 201
    if-eqz p5, :cond_a

    .line 202
    .line 203
    check-cast p3, Ljava/lang/Number;

    .line 204
    .line 205
    invoke-virtual {p3}, Ljava/lang/Number;->shortValue()S

    .line 206
    .line 207
    .line 208
    move-result p3

    .line 209
    int-to-long v0, p3

    .line 210
    invoke-interface {p0, p2, v0, v1}, Lva/a;->bindLong(IJ)V

    .line 211
    .line 212
    .line 213
    goto :goto_3

    .line 214
    :cond_a
    instance-of p5, p3, Ljava/lang/Byte;

    .line 215
    .line 216
    if-eqz p5, :cond_b

    .line 217
    .line 218
    check-cast p3, Ljava/lang/Number;

    .line 219
    .line 220
    invoke-virtual {p3}, Ljava/lang/Number;->byteValue()B

    .line 221
    .line 222
    .line 223
    move-result p3

    .line 224
    int-to-long v0, p3

    .line 225
    invoke-interface {p0, p2, v0, v1}, Lva/a;->bindLong(IJ)V

    .line 226
    .line 227
    .line 228
    goto :goto_3

    .line 229
    :cond_b
    instance-of p5, p3, Ljava/lang/String;

    .line 230
    .line 231
    if-eqz p5, :cond_c

    .line 232
    .line 233
    check-cast p3, Ljava/lang/String;

    .line 234
    .line 235
    invoke-interface {p0, p2, p3}, Lva/a;->bindString(ILjava/lang/String;)V

    .line 236
    .line 237
    .line 238
    goto :goto_3

    .line 239
    :cond_c
    instance-of p5, p3, Ljava/lang/Boolean;

    .line 240
    .line 241
    if-eqz p5, :cond_e

    .line 242
    .line 243
    check-cast p3, Ljava/lang/Boolean;

    .line 244
    .line 245
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 246
    .line 247
    .line 248
    move-result p3

    .line 249
    if-eqz p3, :cond_d

    .line 250
    .line 251
    const-wide/16 v0, 0x1

    .line 252
    .line 253
    goto :goto_4

    .line 254
    :cond_d
    const-wide/16 v0, 0x0

    .line 255
    .line 256
    :goto_4
    invoke-interface {p0, p2, v0, v1}, Lva/a;->bindLong(IJ)V

    .line 257
    .line 258
    .line 259
    goto/16 :goto_3

    .line 260
    .line 261
    :cond_e
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 262
    .line 263
    new-instance p1, Ljava/lang/StringBuilder;

    .line 264
    .line 265
    const-string p4, "Cannot bind "

    .line 266
    .line 267
    invoke-direct {p1, p4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 268
    .line 269
    .line 270
    invoke-virtual {p1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 271
    .line 272
    .line 273
    const-string p3, " at index "

    .line 274
    .line 275
    invoke-virtual {p1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 276
    .line 277
    .line 278
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 279
    .line 280
    .line 281
    const-string p2, " Supported types: Null, ByteArray, Float, Double, Long, Int, Short, Byte, String"

    .line 282
    .line 283
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 284
    .line 285
    .line 286
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 287
    .line 288
    .line 289
    move-result-object p1

    .line 290
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 291
    .line 292
    .line 293
    throw p0

    .line 294
    :cond_f
    check-cast p0, Lwa/j;

    .line 295
    .line 296
    iget-object p0, p0, Lwa/j;->e:Landroid/database/sqlite/SQLiteStatement;

    .line 297
    .line 298
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteStatement;->executeUpdateDelete()I

    .line 299
    .line 300
    .line 301
    move-result p0

    .line 302
    return p0

    .line 303
    :cond_10
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 304
    .line 305
    const-string p1, "Empty values"

    .line 306
    .line 307
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 308
    .line 309
    .line 310
    throw p0
.end method
