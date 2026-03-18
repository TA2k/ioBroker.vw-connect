.class public final Lcom/salesforce/marketingcloud/storage/db/g;
.super Lcom/salesforce/marketingcloud/storage/db/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/storage/f;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness",
        "Range"
    }
.end annotation


# static fields
.field public static final e:Ljava/lang/String; = "inbox_messages"

.field static final f:Ljava/lang/String;

.field private static final g:Ljava/lang/String; = "(start_date IS NULL OR start_date<?) AND (end_date IS NULL OR end_date>?)"

.field private static final h:[Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    const-string v0, "InboxMessageDbStorage"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/storage/db/g;->f:Ljava/lang/String;

    .line 8
    .line 9
    const-string v5, "message_hash"

    .line 10
    .line 11
    const-string v6, "is_dirty"

    .line 12
    .line 13
    const-string v1, "id"

    .line 14
    .line 15
    const-string v2, "start_date"

    .line 16
    .line 17
    const-string v3, "is_deleted"

    .line 18
    .line 19
    const-string v4, "is_read"

    .line 20
    .line 21
    filled-new-array/range {v1 .. v6}, [Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Lcom/salesforce/marketingcloud/storage/db/g;->h:[Ljava/lang/String;

    .line 26
    .line 27
    return-void
.end method

.method public constructor <init>(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;-><init>(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static a(Landroid/database/Cursor;)Lcom/salesforce/marketingcloud/storage/f$b;
    .locals 9

    .line 9
    const-string v0, "start_date"

    invoke-interface {p0, v0}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v0

    .line 10
    new-instance v1, Lcom/salesforce/marketingcloud/storage/f$b;

    .line 11
    const-string v2, "id"

    invoke-interface {p0, v2}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v2

    invoke-interface {p0, v2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v2

    .line 12
    const-string v3, "message_hash"

    invoke-interface {p0, v3}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v3

    invoke-interface {p0, v3}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v3

    .line 13
    invoke-interface {p0, v0}, Landroid/database/Cursor;->isNull(I)Z

    move-result v4

    if-eqz v4, :cond_0

    const/4 v0, 0x0

    move-object v4, v0

    goto :goto_0

    :cond_0
    new-instance v4, Ljava/util/Date;

    invoke-interface {p0, v0}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v5

    invoke-direct {v4, v5, v6}, Ljava/util/Date;-><init>(J)V

    .line 14
    :goto_0
    const-string v0, "is_read"

    invoke-interface {p0, v0}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v0

    invoke-interface {p0, v0}, Landroid/database/Cursor;->getInt(I)I

    move-result v0

    const/4 v5, 0x0

    const/4 v6, 0x1

    if-ne v0, v6, :cond_1

    move v0, v5

    move v5, v6

    goto :goto_1

    :cond_1
    move v0, v5

    .line 15
    :goto_1
    const-string v7, "is_deleted"

    invoke-interface {p0, v7}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v7

    invoke-interface {p0, v7}, Landroid/database/Cursor;->getInt(I)I

    move-result v7

    if-ne v7, v6, :cond_2

    move v7, v6

    goto :goto_2

    :cond_2
    move v7, v6

    move v6, v0

    .line 16
    :goto_2
    const-string v8, "is_dirty"

    invoke-interface {p0, v8}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v8

    invoke-interface {p0, v8}, Landroid/database/Cursor;->getInt(I)I

    move-result p0

    if-ne p0, v7, :cond_3

    goto :goto_3

    :cond_3
    move v7, v0

    :goto_3
    invoke-direct/range {v1 .. v7}, Lcom/salesforce/marketingcloud/storage/f$b;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/Date;ZZZ)V

    return-object v1
.end method

.method private static a(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/database/Cursor;",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;",
            ">;"
        }
    .end annotation

    .line 2
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    if-eqz p0, :cond_3

    .line 3
    invoke-interface {p0}, Landroid/database/Cursor;->moveToFirst()Z

    move-result v1

    if-eqz v1, :cond_2

    .line 4
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 5
    :cond_0
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/storage/db/d;->a(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

    move-result-object v0

    if-eqz v0, :cond_1

    .line 6
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 7
    :cond_1
    invoke-interface {p0}, Landroid/database/Cursor;->moveToNext()Z

    move-result v0

    if-nez v0, :cond_0

    move-object v0, v1

    .line 8
    :cond_2
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    :cond_3
    return-object v0
.end method

.method public static a(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    const-string v0, "DROP TABLE IF EXISTS inbox_messages"

    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    return-void
.end method

.method public static b(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "CREATE TABLE inbox_messages(id TEXT PRIMARY KEY, start_date INTEGER DEFAULT NULL, end_date INTEGER DEFAULT NULL, is_deleted INTEGER DEFAULT 0, is_read INTEGER DEFAULT 0, is_dirty INTEGER DEFAULT 0, message_type INTEGER DEFAULT "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    sget-object v1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->LEGACY:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;

    .line 2
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->getIndex()I

    move-result v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ", message_hash TEXT DEFAULT NULL, notification_message_json TEXT DEFAULT NULL, message_json TEXT);"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 3
    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    return-void
.end method

.method private static b(Lcom/salesforce/marketingcloud/storage/f$a;)[Ljava/lang/String;
    .locals 9

    .line 4
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    move-result-object v0

    .line 5
    sget-object v1, Lcom/salesforce/marketingcloud/storage/db/g$a;->a:[I

    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    move-result v2

    aget v1, v1, v2

    const/4 v2, 0x0

    const-string v3, "1"

    const/4 v4, 0x4

    const-string v5, "0"

    const/4 v6, 0x3

    const/4 v7, 0x2

    const/4 v8, 0x1

    if-eq v1, v8, :cond_3

    if-eq v1, v7, :cond_3

    if-eq v1, v6, :cond_1

    if-ne v1, v4, :cond_0

    goto :goto_0

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string v0, "Unknown MessageStatus while getting message counts."

    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 7
    :cond_1
    :goto_0
    sget-object v1, Lcom/salesforce/marketingcloud/storage/f$a;->d:Lcom/salesforce/marketingcloud/storage/f$a;

    if-ne p0, v1, :cond_2

    goto :goto_1

    :cond_2
    move-object v3, v5

    :goto_1
    new-array p0, v6, [Ljava/lang/String;

    aput-object v0, p0, v2

    aput-object v0, p0, v8

    aput-object v3, p0, v7

    return-object p0

    .line 8
    :cond_3
    sget-object v1, Lcom/salesforce/marketingcloud/storage/f$a;->c:Lcom/salesforce/marketingcloud/storage/f$a;

    if-ne p0, v1, :cond_4

    goto :goto_2

    :cond_4
    move-object v3, v5

    :goto_2
    new-array p0, v4, [Ljava/lang/String;

    aput-object v0, p0, v2

    aput-object v0, p0, v8

    aput-object v3, p0, v7

    aput-object v5, p0, v6

    return-object p0
.end method

.method private static c(Lcom/salesforce/marketingcloud/storage/f$a;)Ljava/lang/String;
    .locals 2

    .line 3
    new-instance v0, Ljava/lang/StringBuilder;

    const/16 v1, 0x65

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    const-string v1, "(start_date IS NULL OR start_date<?) AND (end_date IS NULL OR end_date>?)"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 4
    sget-object v1, Lcom/salesforce/marketingcloud/storage/db/g$a;->a:[I

    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    move-result p0

    aget p0, v1, p0

    const/4 v1, 0x1

    if-eq p0, v1, :cond_2

    const/4 v1, 0x2

    if-eq p0, v1, :cond_2

    const/4 v1, 0x3

    if-eq p0, v1, :cond_1

    const/4 v1, 0x4

    if-ne p0, v1, :cond_0

    goto :goto_0

    .line 5
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string v0, "Unknown MessageStatus while getting message counts."

    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 6
    :cond_1
    :goto_0
    const-string p0, " AND is_deleted=?"

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_1

    .line 7
    :cond_2
    const-string p0, " AND is_read=? AND is_deleted=?"

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 8
    :goto_1
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method private static c(Landroid/database/sqlite/SQLiteDatabase;)Z
    .locals 3

    .line 1
    :try_start_0
    const-string v0, "SELECT id,start_date,end_date,is_deleted,is_read,is_dirty,message_hash,message_json,message_type,notification_message_json FROM inbox_messages"

    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    const/4 p0, 0x1

    return p0

    :catch_0
    move-exception p0

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/g;->f:Ljava/lang/String;

    const-string v1, "inbox_messages"

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v2, "%s is invalid"

    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p0, 0x0

    return p0
.end method

.method public static d(Landroid/database/sqlite/SQLiteDatabase;)Z
    .locals 4

    .line 1
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/g;->c(Landroid/database/sqlite/SQLiteDatabase;)Z

    move-result v0

    if-nez v0, :cond_0

    .line 2
    :try_start_0
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/g;->a(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 3
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/g;->b(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 4
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/g;->c(Landroid/database/sqlite/SQLiteDatabase;)Z

    move-result p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return p0

    :catch_0
    move-exception p0

    .line 5
    sget-object v1, Lcom/salesforce/marketingcloud/storage/db/g;->f:Ljava/lang/String;

    const-string v2, "inbox_messages"

    filled-new-array {v2}, [Ljava/lang/Object;

    move-result-object v2

    const-string v3, "Unable to recover %s"

    invoke-static {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    return v0
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/storage/f$a;)I
    .locals 2

    .line 31
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    .line 32
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/g;->c(Lcom/salesforce/marketingcloud/storage/f$a;)Ljava/lang/String;

    move-result-object v0

    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/g;->b(Lcom/salesforce/marketingcloud/storage/f$a;)[Ljava/lang/String;

    move-result-object p1

    .line 33
    const-string v1, "inbox_messages"

    invoke-static {p0, v1, v0, p1}, Landroid/database/DatabaseUtils;->queryNumEntries(Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)J

    move-result-wide p0

    long-to-int p0, p0

    return p0
.end method

.method public a(Ljava/util/List;)I
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)I"
        }
    .end annotation

    .line 20
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    return v1

    .line 21
    :cond_0
    :try_start_0
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->c(Ljava/util/Collection;)I

    move-result p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return p0

    .line 22
    :catch_0
    sget-object p1, Lcom/salesforce/marketingcloud/storage/db/g;->f:Ljava/lang/String;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/db/g;->o()Ljava/lang/String;

    move-result-object p0

    filled-new-array {p0}, [Ljava/lang/Object;

    move-result-object p0

    const-string v0, "Unable to clean up %s table."

    invoke-static {p1, v0, p0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return v1
.end method

.method public a(Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;
    .locals 8

    .line 23
    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object v3

    const/4 v6, 0x0

    const-string v7, "1"

    const/4 v1, 0x0

    const-string v2, "id=?"

    const/4 v4, 0x0

    const/4 v5, 0x0

    move-object v0, p0

    invoke-virtual/range {v0 .. v7}, Lcom/salesforce/marketingcloud/storage/db/b;->a([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p0

    const/4 p1, 0x0

    if-eqz p0, :cond_1

    .line 24
    invoke-interface {p0}, Landroid/database/Cursor;->moveToFirst()Z

    move-result v0

    if-eqz v0, :cond_0

    .line 25
    invoke-static {p0, p2}, Lcom/salesforce/marketingcloud/storage/db/d;->a(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

    move-result-object p1

    .line 26
    :cond_0
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    :cond_1
    return-object p1
.end method

.method public a(Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/storage/f$a;)Ljava/util/List;
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            "Lcom/salesforce/marketingcloud/storage/f$a;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;",
            ">;"
        }
    .end annotation

    .line 27
    invoke-static {p2}, Lcom/salesforce/marketingcloud/storage/db/g;->c(Lcom/salesforce/marketingcloud/storage/f$a;)Ljava/lang/String;

    move-result-object v2

    .line 28
    invoke-static {p2}, Lcom/salesforce/marketingcloud/storage/db/g;->b(Lcom/salesforce/marketingcloud/storage/f$a;)[Ljava/lang/String;

    move-result-object v3

    new-instance p2, Ljava/lang/StringBuilder;

    const-string v0, "IFNULL(start_date, "

    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 29
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    invoke-virtual {p2, v0, v1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const-string v0, ") DESC"

    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v6

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v1, 0x0

    move-object v0, p0

    .line 30
    invoke-virtual/range {v0 .. v6}, Lcom/salesforce/marketingcloud/storage/db/b;->a([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p0

    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/storage/db/g;->a(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    move-result-object p0

    return-object p0
.end method

.method public a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;Lcom/salesforce/marketingcloud/util/Crypto;)V
    .locals 1

    .line 17
    invoke-static {p1, p2}, Lcom/salesforce/marketingcloud/storage/db/d;->a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;Lcom/salesforce/marketingcloud/util/Crypto;)Landroid/content/ContentValues;

    move-result-object p2

    .line 18
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->id()Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    const-string v0, "id = ?"

    invoke-virtual {p0, p2, v0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I

    move-result p1

    if-nez p1, :cond_0

    .line 19
    invoke-virtual {p0, p2}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Landroid/content/ContentValues;)J

    :cond_0
    return-void
.end method

.method public b()V
    .locals 3

    .line 9
    new-instance v0, Landroid/content/ContentValues;

    const/4 v1, 0x2

    invoke-direct {v0, v1}, Landroid/content/ContentValues;-><init>(I)V

    const/4 v1, 0x1

    .line 10
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    const-string v2, "is_dirty"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 11
    const-string v2, "is_deleted"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 12
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v1

    invoke-static {v1, v2}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    move-result-object v1

    .line 13
    filled-new-array {v1, v1}, [Ljava/lang/String;

    move-result-object v1

    const-string v2, "(start_date IS NULL OR start_date<?) AND (end_date IS NULL OR end_date>?) AND is_deleted=0"

    invoke-virtual {p0, v0, v2, v1}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I

    return-void
.end method

.method public b([Ljava/lang/String;)V
    .locals 3

    .line 14
    array-length v0, p1

    if-lez v0, :cond_0

    .line 15
    new-instance v0, Landroid/content/ContentValues;

    invoke-direct {v0}, Landroid/content/ContentValues;-><init>()V

    const/4 v1, 0x0

    .line 16
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    const-string v2, "is_dirty"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 17
    :try_start_0
    invoke-static {p1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    invoke-virtual {p0, v0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Landroid/content/ContentValues;Ljava/util/Collection;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    .line 18
    :catch_0
    sget-object p1, Lcom/salesforce/marketingcloud/storage/db/g;->f:Ljava/lang/String;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/db/g;->o()Ljava/lang/String;

    move-result-object p0

    filled-new-array {p0}, [Ljava/lang/Object;

    move-result-object p0

    const-string v0, "Unable to update %s table."

    invoke-static {p1, v0, p0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    return-void
.end method

.method public c(Ljava/lang/String;)V
    .locals 3

    .line 9
    new-instance v0, Landroid/content/ContentValues;

    const/4 v1, 0x2

    invoke-direct {v0, v1}, Landroid/content/ContentValues;-><init>(I)V

    const/4 v1, 0x1

    .line 10
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    const-string v2, "is_dirty"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 11
    const-string v2, "is_deleted"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 12
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v1

    invoke-static {v1, v2}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    move-result-object v1

    .line 13
    filled-new-array {p1, v1, v1}, [Ljava/lang/String;

    move-result-object p1

    const-string v1, "id=? AND (start_date IS NULL OR start_date<?) AND (end_date IS NULL OR end_date>?) AND is_deleted=0"

    invoke-virtual {p0, v0, v1, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I

    return-void
.end method

.method public d(Ljava/lang/String;)V
    .locals 2

    .line 6
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    move-result-object v0

    .line 7
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    filled-new-array {p1, v0, v0}, [Ljava/lang/String;

    move-result-object p1

    const-string v0, "UPDATE inbox_messages SET   is_read = 1,  is_dirty = CASE WHEN is_dirty=1 OR is_deleted=0 THEN 1 ELSE 0 END WHERE   id=? AND (start_date IS NULL OR start_date<?) AND (end_date IS NULL OR end_date>?) AND is_read=0"

    invoke-virtual {p0, v0, p1}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public e(Ljava/lang/String;)Z
    .locals 2

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    .line 2
    .line 3
    filled-new-array {p1}, [Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const-string v0, "inbox_messages"

    .line 8
    .line 9
    const-string v1, "id=?"

    .line 10
    .line 11
    invoke-static {p0, v0, v1, p1}, Landroid/database/DatabaseUtils;->queryNumEntries(Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)J

    .line 12
    .line 13
    .line 14
    move-result-wide p0

    .line 15
    const-wide/16 v0, 0x0

    .line 16
    .line 17
    cmp-long p0, p0, v0

    .line 18
    .line 19
    if-lez p0, :cond_0

    .line 20
    .line 21
    const/4 p0, 0x1

    .line 22
    return p0

    .line 23
    :cond_0
    const/4 p0, 0x0

    .line 24
    return p0
.end method

.method public f(Ljava/lang/String;)Lcom/salesforce/marketingcloud/storage/f$b;
    .locals 2

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/g;->h:[Ljava/lang/String;

    .line 2
    .line 3
    filled-new-array {p1}, [Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const-string v1, "id=?"

    .line 8
    .line 9
    invoke-virtual {p0, v0, v1, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->a([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    const/4 p1, 0x0

    .line 14
    if-eqz p0, :cond_1

    .line 15
    .line 16
    invoke-interface {p0}, Landroid/database/Cursor;->moveToFirst()Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/g;->a(Landroid/database/Cursor;)Lcom/salesforce/marketingcloud/storage/f$b;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    :cond_0
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    .line 27
    .line 28
    .line 29
    :cond_1
    return-object p1
.end method

.method public h()I
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/storage/db/b;->i(Ljava/lang/String;)I

    .line 3
    .line 4
    .line 5
    move-result p0

    .line 6
    return p0
.end method

.method public i()Ljava/util/List;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/storage/f$b;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/g;->h:[Ljava/lang/String;

    .line 2
    .line 3
    const-string v1, "is_dirty=1"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-virtual {p0, v0, v1, v2}, Lcom/salesforce/marketingcloud/storage/db/b;->a([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    if-eqz p0, :cond_2

    .line 11
    .line 12
    invoke-interface {p0}, Landroid/database/Cursor;->moveToFirst()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    new-instance v0, Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-interface {p0}, Landroid/database/Cursor;->getCount()I

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 25
    .line 26
    .line 27
    :cond_0
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/g;->a(Landroid/database/Cursor;)Lcom/salesforce/marketingcloud/storage/f$b;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-interface {p0}, Landroid/database/Cursor;->moveToNext()Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-nez v1, :cond_0

    .line 39
    .line 40
    move-object v2, v0

    .line 41
    :cond_1
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    .line 42
    .line 43
    .line 44
    :cond_2
    if-eqz v2, :cond_3

    .line 45
    .line 46
    return-object v2

    .line 47
    :cond_3
    sget-object p0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 48
    .line 49
    return-object p0
.end method

.method public j()V
    .locals 2

    .line 1
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    .line 10
    .line 11
    filled-new-array {v0, v0}, [Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, "UPDATE inbox_messages SET   is_read = 1,  is_dirty = CASE WHEN is_dirty=1 OR is_deleted=0 THEN 1 ELSE 0 END WHERE (start_date IS NULL OR start_date<?) AND (end_date IS NULL OR end_date>?) AND is_read=0"

    .line 16
    .line 17
    invoke-virtual {p0, v1, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public m(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;",
            ">;"
        }
    .end annotation

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0, v0, v0}, Lcom/salesforce/marketingcloud/storage/db/b;->a([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/storage/db/g;->a(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public o()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "inbox_messages"

    .line 2
    .line 3
    return-object p0
.end method
