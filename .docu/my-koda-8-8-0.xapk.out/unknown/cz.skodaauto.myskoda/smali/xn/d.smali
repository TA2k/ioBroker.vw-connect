.class public final synthetic Lxn/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lzn/b;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lqn/s;

.field public final synthetic f:Lrn/j;


# direct methods
.method public synthetic constructor <init>(Lqn/s;Lrn/j;I)V
    .locals 0

    .line 1
    iput p3, p0, Lxn/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lxn/d;->e:Lqn/s;

    .line 4
    .line 5
    iput-object p2, p0, Lxn/d;->f:Lrn/j;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final execute()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lxn/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lxn/d;->e:Lqn/s;

    .line 7
    .line 8
    iget-object v0, v0, Lqn/s;->c:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lyn/d;

    .line 11
    .line 12
    check-cast v0, Lyn/h;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    new-instance v1, Lxn/e;

    .line 18
    .line 19
    iget-object p0, p0, Lxn/d;->f:Lrn/j;

    .line 20
    .line 21
    invoke-direct {v1, v0, p0}, Lxn/e;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0, v1}, Lyn/h;->d(Lyn/f;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    check-cast p0, Ljava/lang/Iterable;

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_0
    iget-object v0, p0, Lxn/d;->f:Lrn/j;

    .line 32
    .line 33
    iget-object p0, p0, Lxn/d;->e:Lqn/s;

    .line 34
    .line 35
    iget-object p0, p0, Lqn/s;->c:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p0, Lyn/d;

    .line 38
    .line 39
    check-cast p0, Lyn/h;

    .line 40
    .line 41
    invoke-virtual {p0}, Lyn/h;->a()Landroid/database/sqlite/SQLiteDatabase;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    invoke-virtual {v1}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 46
    .line 47
    .line 48
    :try_start_0
    invoke-static {v1, v0}, Lyn/h;->b(Landroid/database/sqlite/SQLiteDatabase;Lrn/j;)Ljava/lang/Long;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    if-nez v0, :cond_0

    .line 53
    .line 54
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_0
    invoke-virtual {p0}, Lyn/h;->a()Landroid/database/sqlite/SQLiteDatabase;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    const-string v2, "SELECT 1 FROM events WHERE context_id = ? LIMIT 1"

    .line 62
    .line 63
    invoke-virtual {v0}, Ljava/lang/Long;->toString()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    filled-new-array {v0}, [Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    invoke-virtual {p0, v2, v0}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 72
    .line 73
    .line 74
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 75
    :try_start_1
    invoke-interface {p0}, Landroid/database/Cursor;->moveToNext()Z

    .line 76
    .line 77
    .line 78
    move-result v0

    .line 79
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 80
    .line 81
    .line 82
    move-result-object v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 83
    :try_start_2
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    .line 84
    .line 85
    .line 86
    move-object p0, v0

    .line 87
    :goto_0
    invoke-virtual {v1}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 88
    .line 89
    .line 90
    invoke-virtual {v1}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 91
    .line 92
    .line 93
    return-object p0

    .line 94
    :catchall_0
    move-exception p0

    .line 95
    goto :goto_1

    .line 96
    :catchall_1
    move-exception v0

    .line 97
    :try_start_3
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    .line 98
    .line 99
    .line 100
    throw v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 101
    :goto_1
    invoke-virtual {v1}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 102
    .line 103
    .line 104
    throw p0

    .line 105
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
