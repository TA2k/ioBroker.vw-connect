.class public abstract Lcom/salesforce/marketingcloud/storage/db/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# static fields
.field protected static final d:Ljava/lang/String; = "%s = ?"


# instance fields
.field protected final c:Landroid/database/sqlite/SQLiteDatabase;


# direct methods
.method public constructor <init>(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    .line 5
    .line 6
    return-void
.end method

.method private a(Ljava/lang/String;Ljava/util/Collection;Z)I
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;Z)I"
        }
    .end annotation

    .line 10
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {v0}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 11
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/storage/db/b;->b(Ljava/lang/String;Ljava/util/Collection;)V

    .line 12
    iget-object p2, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    const-string v0, "id IN(SELECT %1$s.id FROM %1$s LEFT JOIN tmp_%1$s ON %1$s.id = tmp_%1$s.id WHERE tmp_%1$s.id %2$s)"

    if-eqz p3, :cond_0

    .line 13
    const-string p3, "IS NULL"

    goto :goto_0

    :catch_0
    move-exception p1

    goto :goto_1

    .line 14
    :cond_0
    const-string p3, "IS NOT NULL"

    :goto_0
    filled-new-array {p1, p3}, [Ljava/lang/Object;

    move-result-object p3

    .line 15
    invoke-static {v0, p3}, Lcom/salesforce/marketingcloud/storage/db/c;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p3

    const/4 v0, 0x0

    invoke-virtual {p2, p1, p3, v0}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I

    move-result p2

    .line 16
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->h(Ljava/lang/String;)V

    .line 17
    iget-object p1, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V

    .line 18
    iget-object p1, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V
    :try_end_0
    .catch Landroid/database/SQLException; {:try_start_0 .. :try_end_0} :catch_0

    return p2

    .line 19
    :goto_1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 20
    throw p1
.end method


# virtual methods
.method public final a(Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I
    .locals 1

    .line 8
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/db/b;->o()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v0, p0, p1, p2, p3}, Landroid/database/sqlite/SQLiteDatabase;->update(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I

    move-result p0

    return p0
.end method

.method public final a(Ljava/lang/String;Ljava/util/Collection;)I
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)I"
        }
    .end annotation

    const/4 v0, 0x1

    .line 9
    invoke-direct {p0, p1, p2, v0}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Ljava/lang/String;Ljava/util/Collection;Z)I

    move-result p0

    return p0
.end method

.method public final a(Ljava/lang/String;[Ljava/lang/String;)I
    .locals 1

    .line 7
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/db/b;->o()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v0, p0, p1, p2}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I

    move-result p0

    return p0
.end method

.method public final a(Landroid/content/ContentValues;)J
    .locals 2

    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/db/b;->o()Ljava/lang/String;

    move-result-object p0

    const/4 v1, 0x0

    invoke-virtual {v0, p0, v1, p1}, Landroid/database/sqlite/SQLiteDatabase;->insert(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J

    move-result-wide p0

    return-wide p0
.end method

.method public final a(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;
    .locals 8

    .line 3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v5, 0x0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    invoke-virtual/range {v0 .. v7}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p0

    return-object p0
.end method

.method public final a([Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    .locals 8

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    .line 5
    invoke-virtual/range {v0 .. v7}, Lcom/salesforce/marketingcloud/storage/db/b;->a([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p0

    return-object p0
.end method

.method public final a([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;
    .locals 8

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    .line 4
    invoke-virtual/range {v0 .. v7}, Lcom/salesforce/marketingcloud/storage/db/b;->a([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p0

    return-object p0
.end method

.method public final a([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    .locals 10

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/db/b;->o()Ljava/lang/String;

    move-result-object v2

    const/4 v1, 0x0

    const/4 v9, 0x0

    move-object v3, p1

    move-object v4, p2

    move-object v5, p3

    move-object v6, p4

    move-object v7, p5

    move-object/from16 v8, p6

    invoke-virtual/range {v0 .. v9}, Landroid/database/sqlite/SQLiteDatabase;->query(ZLjava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p0

    return-object p0
.end method

.method public final a([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    .locals 10

    .line 2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/db/b;->o()Ljava/lang/String;

    move-result-object v2

    const/4 v1, 0x0

    move-object v3, p1

    move-object v4, p2

    move-object v5, p3

    move-object v6, p4

    move-object v7, p5

    move-object/from16 v8, p6

    move-object/from16 v9, p7

    invoke-virtual/range {v0 .. v9}, Landroid/database/sqlite/SQLiteDatabase;->query(ZLjava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p0

    return-object p0
.end method

.method public final a(Landroid/content/ContentValues;Ljava/util/Collection;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/content/ContentValues;",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 21
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {v0}, Landroid/database/sqlite/SQLiteDatabase;->beginTransactionNonExclusive()V

    .line 22
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/db/b;->o()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p0, v0, p2}, Lcom/salesforce/marketingcloud/storage/db/b;->b(Ljava/lang/String;Ljava/util/Collection;)V

    .line 23
    const-string p2, "id IN(SELECT %1$s.id FROM %1$s LEFT JOIN tmp_%1$s ON %1$s.id = tmp_%1$s.id WHERE tmp_%1$s.id IS NOT NULL)"

    .line 24
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/db/b;->o()Ljava/lang/String;

    move-result-object v0

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    .line 25
    invoke-static {p2, v0}, Lcom/salesforce/marketingcloud/storage/db/c;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    const/4 v0, 0x0

    invoke-virtual {p0, p1, p2, v0}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I

    .line 26
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/db/b;->o()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->h(Ljava/lang/String;)V

    .line 27
    iget-object p1, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V

    .line 28
    iget-object p1, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V
    :try_end_0
    .catch Landroid/database/SQLException; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p1

    .line 29
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 30
    throw p1
.end method

.method public b(Ljava/lang/String;Ljava/util/Collection;)V
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    .line 2
    .line 3
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const-string v2, "DROP TABLE IF EXISTS tmp_%s;"

    .line 8
    .line 9
    invoke-static {v2, v1}, Lcom/salesforce/marketingcloud/storage/db/c;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-virtual {v0, v1}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    .line 17
    .line 18
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    const-string v2, "CREATE TEMPORARY TABLE tmp_%s(id VARCHAR);"

    .line 23
    .line 24
    invoke-static {v2, v1}, Lcom/salesforce/marketingcloud/storage/db/c;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    invoke-virtual {v0, v1}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    new-instance v0, Landroid/content/ContentValues;

    .line 32
    .line 33
    invoke-direct {v0}, Landroid/content/ContentValues;-><init>()V

    .line 34
    .line 35
    .line 36
    invoke-interface {p2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 37
    .line 38
    .line 39
    move-result-object p2

    .line 40
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    if-eqz v1, :cond_0

    .line 45
    .line 46
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    check-cast v1, Ljava/lang/String;

    .line 51
    .line 52
    const-string v2, "id"

    .line 53
    .line 54
    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iget-object v1, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    .line 58
    .line 59
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    const-string v3, "tmp_%s"

    .line 64
    .line 65
    invoke-static {v3, v2}, Lcom/salesforce/marketingcloud/storage/db/c;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    const/4 v3, 0x0

    .line 70
    invoke-virtual {v1, v2, v3, v0}, Landroid/database/sqlite/SQLiteDatabase;->insert(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_0
    return-void
.end method

.method public final c(Ljava/util/Collection;)I
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)I"
        }
    .end annotation

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/db/b;->o()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-direct {p0, v0, p1, v1}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Ljava/lang/String;Ljava/util/Collection;Z)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public h(Ljava/lang/String;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    .line 2
    .line 3
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const-string v0, "DROP TABLE IF EXISTS tmp_%s;"

    .line 8
    .line 9
    invoke-static {v0, p1}, Lcom/salesforce/marketingcloud/storage/db/c;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-virtual {p0, p1}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final i(Ljava/lang/String;)I
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Ljava/lang/String;[Ljava/lang/String;)I

    .line 3
    .line 4
    .line 5
    move-result p0

    .line 6
    return p0
.end method

.method public abstract o()Ljava/lang/String;
.end method
