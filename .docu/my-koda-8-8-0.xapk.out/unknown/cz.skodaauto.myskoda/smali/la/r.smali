.class public final Lla/r;
.super Lla/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final c:Lla/b;

.field public final d:Lka/u;

.field public final e:Ljava/util/List;

.field public final f:Lna/b;

.field public final g:Landroidx/sqlite/db/SupportSQLiteOpenHelper;

.field public h:Landroidx/sqlite/db/SupportSQLiteDatabase;


# direct methods
.method public constructor <init>(Lla/b;Lka/u;Ljd/b;)V
    .locals 11

    iget-object v0, p1, Lla/b;->g:Lla/t;

    iget-object v1, p1, Lla/b;->c:Landroidx/sqlite/db/a;

    iget-object v2, p1, Lla/b;->t:Lua/b;

    iget-object v5, p1, Lla/b;->b:Ljava/lang/String;

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lla/r;->c:Lla/b;

    .line 3
    iput-object p2, p0, Lla/r;->d:Lka/u;

    .line 4
    iget-object v3, p1, Lla/b;->e:Ljava/util/List;

    if-nez v3, :cond_0

    sget-object v3, Lmx0/s;->d:Lmx0/s;

    :cond_0
    iput-object v3, p0, Lla/r;->e:Ljava/util/List;

    const/4 v9, 0x1

    .line 5
    const-string v10, ":memory:"

    if-nez v2, :cond_3

    if-eqz v1, :cond_2

    .line 6
    iget-object v4, p1, Lla/b;->a:Landroid/content/Context;

    .line 7
    const-string p1, "context"

    invoke-static {v4, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    new-instance v6, Lb11/a;

    .line 9
    iget p1, p2, Lka/u;->a:I

    .line 10
    invoke-direct {v6, p0, p1}, Lb11/a;-><init>(Lla/r;I)V

    .line 11
    new-instance v3, Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;

    const/4 v7, 0x0

    const/4 v8, 0x0

    invoke-direct/range {v3 .. v8}, Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;-><init>(Landroid/content/Context;Ljava/lang/String;Lb11/a;ZZ)V

    .line 12
    invoke-interface {v1, v3}, Landroidx/sqlite/db/a;->create(Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;)Landroidx/sqlite/db/SupportSQLiteOpenHelper;

    move-result-object p1

    iput-object p1, p0, Lla/r;->g:Landroidx/sqlite/db/SupportSQLiteOpenHelper;

    .line 13
    new-instance p2, Lna/q;

    .line 14
    new-instance v1, Lt1/j0;

    invoke-direct {v1, p1}, Lt1/j0;-><init>(Landroidx/sqlite/db/SupportSQLiteOpenHelper;)V

    if-nez v5, :cond_1

    move-object v5, v10

    .line 15
    :cond_1
    invoke-direct {p2, v1, v5, p3}, Lna/q;-><init>(Lua/b;Ljava/lang/String;Lay0/n;)V

    .line 16
    iput-object p2, p0, Lla/r;->f:Lna/b;

    goto/16 :goto_3

    .line 17
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "SQLiteManager was constructed with both null driver and open helper factory!"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_3
    const/4 p1, 0x0

    .line 18
    iput-object p1, p0, Lla/r;->g:Landroidx/sqlite/db/SupportSQLiteOpenHelper;

    .line 19
    invoke-interface {v2}, Lua/b;->j()Z

    move-result p1

    if-eqz p1, :cond_5

    .line 20
    new-instance p1, Lna/q;

    .line 21
    new-instance p2, Lb81/c;

    invoke-direct {p2, p0, v2}, Lb81/c;-><init>(Lla/r;Lua/b;)V

    if-nez v5, :cond_4

    move-object v5, v10

    .line 22
    :cond_4
    invoke-direct {p1, p2, v5, p3}, Lna/q;-><init>(Lua/b;Ljava/lang/String;Lay0/n;)V

    goto :goto_2

    :cond_5
    if-nez v5, :cond_6

    .line 23
    new-instance p1, Lb81/c;

    invoke-direct {p1, p0, v2}, Lb81/c;-><init>(Lla/r;Lua/b;)V

    .line 24
    new-instance p2, Lna/f;

    invoke-direct {p2, p1}, Lna/f;-><init>(Lb81/c;)V

    move-object p1, p2

    goto :goto_2

    .line 25
    :cond_6
    new-instance p1, Lb81/c;

    invoke-direct {p1, p0, v2}, Lb81/c;-><init>(Lla/r;Lua/b;)V

    .line 26
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result p2

    const/16 p3, 0x27

    const/4 v1, 0x2

    if-eq p2, v9, :cond_8

    if-ne p2, v1, :cond_7

    const/4 p2, 0x4

    goto :goto_0

    .line 27
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    new-instance p1, Ljava/lang/StringBuilder;

    const-string p2, "Can\'t get max number of reader for journal mode \'"

    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, p3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_8
    move p2, v9

    .line 29
    :goto_0
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v2

    if-eq v2, v9, :cond_a

    if-ne v2, v1, :cond_9

    goto :goto_1

    .line 30
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 31
    new-instance p1, Ljava/lang/StringBuilder;

    const-string p2, "Can\'t get max number of writers for journal mode \'"

    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, p3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 32
    :cond_a
    :goto_1
    new-instance p3, Lna/f;

    invoke-direct {p3, p1, v5, p2}, Lna/f;-><init>(Lb81/c;Ljava/lang/String;I)V

    move-object p1, p3

    .line 33
    :goto_2
    iput-object p1, p0, Lla/r;->f:Lna/b;

    .line 34
    :goto_3
    sget-object p1, Lla/t;->f:Lla/t;

    if-ne v0, p1, :cond_b

    goto :goto_4

    :cond_b
    const/4 v9, 0x0

    .line 35
    :goto_4
    iget-object p0, p0, Lla/r;->g:Landroidx/sqlite/db/SupportSQLiteOpenHelper;

    if-eqz p0, :cond_c

    invoke-interface {p0, v9}, Landroidx/sqlite/db/SupportSQLiteOpenHelper;->setWriteAheadLoggingEnabled(Z)V

    :cond_c
    return-void
.end method

.method public constructor <init>(Lla/b;Lkq0/a;Ljd/b;)V
    .locals 27

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    .line 36
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 37
    iput-object v1, v0, Lla/r;->c:Lla/b;

    .line 38
    new-instance v2, Lla/q;

    const/4 v3, -0x1

    .line 39
    const-string v4, ""

    invoke-direct {v2, v4, v3, v4}, Lka/u;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 40
    iput-object v2, v0, Lla/r;->d:Lka/u;

    .line 41
    iget-object v2, v1, Lla/b;->e:Ljava/util/List;

    sget-object v3, Lmx0/s;->d:Lmx0/s;

    if-nez v2, :cond_0

    move-object v4, v3

    goto :goto_0

    :cond_0
    move-object v4, v2

    :goto_0
    iput-object v4, v0, Lla/r;->e:Ljava/util/List;

    .line 42
    new-instance v4, Lla/p;

    const/4 v5, 0x0

    invoke-direct {v4, v0, v5}, Lla/p;-><init>(Ljava/lang/Object;I)V

    if-nez v2, :cond_1

    move-object v2, v3

    .line 43
    :cond_1
    check-cast v2, Ljava/util/Collection;

    .line 44
    new-instance v0, Lfb/a;

    invoke-direct {v0, v4}, Lfb/a;-><init>(Lla/p;)V

    .line 45
    invoke-static {v2, v0}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    move-result-object v10

    .line 46
    iget-object v6, v1, Lla/b;->a:Landroid/content/Context;

    .line 47
    iget-object v7, v1, Lla/b;->b:Ljava/lang/String;

    .line 48
    iget-object v8, v1, Lla/b;->c:Landroidx/sqlite/db/a;

    .line 49
    iget-object v9, v1, Lla/b;->d:Lfb/k;

    .line 50
    iget-boolean v11, v1, Lla/b;->f:Z

    .line 51
    iget-object v12, v1, Lla/b;->g:Lla/t;

    .line 52
    iget-object v13, v1, Lla/b;->h:Ljava/util/concurrent/Executor;

    .line 53
    iget-object v14, v1, Lla/b;->i:Ljava/util/concurrent/Executor;

    .line 54
    iget-object v15, v1, Lla/b;->j:Landroid/content/Intent;

    .line 55
    iget-boolean v0, v1, Lla/b;->k:Z

    .line 56
    iget-boolean v2, v1, Lla/b;->l:Z

    .line 57
    iget-object v3, v1, Lla/b;->m:Ljava/util/Set;

    .line 58
    iget-object v4, v1, Lla/b;->n:Ljava/lang/String;

    .line 59
    iget-object v5, v1, Lla/b;->o:Ljava/io/File;

    move/from16 v16, v0

    .line 60
    iget-object v0, v1, Lla/b;->p:Ljava/util/concurrent/Callable;

    move-object/from16 v21, v0

    .line 61
    iget-object v0, v1, Lla/b;->q:Ljava/util/List;

    move/from16 v17, v2

    .line 62
    iget-object v2, v1, Lla/b;->r:Ljava/util/List;

    move-object/from16 v18, v3

    .line 63
    iget-boolean v3, v1, Lla/b;->s:Z

    move/from16 v24, v3

    .line 64
    iget-object v3, v1, Lla/b;->t:Lua/b;

    .line 65
    iget-object v1, v1, Lla/b;->u:Lpx0/g;

    move-object/from16 v26, v1

    .line 66
    const-string v1, "context"

    invoke-static {v6, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "migrationContainer"

    invoke-static {v9, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "queryExecutor"

    invoke-static {v13, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "transactionExecutor"

    invoke-static {v14, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "typeConverters"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "autoMigrationSpecs"

    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v20, v5

    .line 67
    new-instance v5, Lla/b;

    move-object/from16 v22, v0

    move-object/from16 v23, v2

    move-object/from16 v25, v3

    move-object/from16 v19, v4

    invoke-direct/range {v5 .. v26}, Lla/b;-><init>(Landroid/content/Context;Ljava/lang/String;Landroidx/sqlite/db/a;Lfb/k;Ljava/util/List;ZLla/t;Ljava/util/concurrent/Executor;Ljava/util/concurrent/Executor;Landroid/content/Intent;ZZLjava/util/Set;Ljava/lang/String;Ljava/io/File;Ljava/util/concurrent/Callable;Ljava/util/List;Ljava/util/List;ZLua/b;Lpx0/g;)V

    move-object/from16 v0, p2

    .line 68
    invoke-virtual {v0, v5}, Lkq0/a;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v0, 0x0

    throw v0
.end method
