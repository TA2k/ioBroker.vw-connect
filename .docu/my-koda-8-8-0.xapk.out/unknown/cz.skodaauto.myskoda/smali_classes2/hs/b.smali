.class public final synthetic Lhs/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhs/g;
.implements Lzn/b;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:J

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lhs/f;Ljava/lang/Object;JLjava/util/concurrent/TimeUnit;I)V
    .locals 0

    .line 1
    iput p6, p0, Lhs/b;->d:I

    iput-object p1, p0, Lhs/b;->e:Ljava/lang/Object;

    iput-object p2, p0, Lhs/b;->h:Ljava/lang/Object;

    iput-wide p3, p0, Lhs/b;->f:J

    iput-object p5, p0, Lhs/b;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lqn/s;Ljava/lang/Iterable;Lrn/j;J)V
    .locals 1

    .line 2
    const/4 v0, 0x2

    iput v0, p0, Lhs/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lhs/b;->e:Ljava/lang/Object;

    iput-object p2, p0, Lhs/b;->h:Ljava/lang/Object;

    iput-object p3, p0, Lhs/b;->g:Ljava/lang/Object;

    iput-wide p4, p0, Lhs/b;->f:J

    return-void
.end method


# virtual methods
.method public a(La0/j;)Ljava/util/concurrent/ScheduledFuture;
    .locals 6

    .line 1
    iget v0, p0, Lhs/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lhs/b;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lhs/f;

    .line 9
    .line 10
    iget-object v1, p0, Lhs/b;->h:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Ljava/util/concurrent/Callable;

    .line 13
    .line 14
    iget-object v2, p0, Lhs/b;->g:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Ljava/util/concurrent/TimeUnit;

    .line 17
    .line 18
    iget-object v3, v0, Lhs/f;->e:Ljava/util/concurrent/ScheduledExecutorService;

    .line 19
    .line 20
    new-instance v4, Lfb/d;

    .line 21
    .line 22
    const/4 v5, 0x1

    .line 23
    invoke-direct {v4, v0, v1, p1, v5}, Lfb/d;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 24
    .line 25
    .line 26
    iget-wide p0, p0, Lhs/b;->f:J

    .line 27
    .line 28
    invoke-interface {v3, v4, p0, p1, v2}, Ljava/util/concurrent/ScheduledExecutorService;->schedule(Ljava/util/concurrent/Callable;JLjava/util/concurrent/TimeUnit;)Ljava/util/concurrent/ScheduledFuture;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :pswitch_0
    iget-object v0, p0, Lhs/b;->e:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v0, Lhs/f;

    .line 36
    .line 37
    iget-object v1, p0, Lhs/b;->h:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v1, Ljava/lang/Runnable;

    .line 40
    .line 41
    iget-object v2, p0, Lhs/b;->g:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v2, Ljava/util/concurrent/TimeUnit;

    .line 44
    .line 45
    iget-object v3, v0, Lhs/f;->e:Ljava/util/concurrent/ScheduledExecutorService;

    .line 46
    .line 47
    new-instance v4, Lhs/e;

    .line 48
    .line 49
    const/4 v5, 0x1

    .line 50
    invoke-direct {v4, v0, v1, p1, v5}, Lhs/e;-><init>(Lhs/f;Ljava/lang/Runnable;La0/j;I)V

    .line 51
    .line 52
    .line 53
    iget-wide p0, p0, Lhs/b;->f:J

    .line 54
    .line 55
    invoke-interface {v3, v4, p0, p1, v2}, Ljava/util/concurrent/ScheduledExecutorService;->schedule(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Ljava/util/concurrent/ScheduledFuture;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public execute()Ljava/lang/Object;
    .locals 10

    .line 1
    iget-object v0, p0, Lhs/b;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lqn/s;

    .line 4
    .line 5
    iget-object v1, p0, Lhs/b;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Ljava/lang/Iterable;

    .line 8
    .line 9
    iget-object v2, p0, Lhs/b;->g:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v2, Lrn/j;

    .line 12
    .line 13
    iget-object v3, v0, Lqn/s;->c:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v3, Lyn/d;

    .line 16
    .line 17
    check-cast v3, Lyn/h;

    .line 18
    .line 19
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    const/4 v5, 0x0

    .line 31
    if-nez v4, :cond_0

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_0
    new-instance v4, Ljava/lang/StringBuilder;

    .line 35
    .line 36
    const-string v6, "UPDATE events SET num_attempts = num_attempts + 1 WHERE _id in "

    .line 37
    .line 38
    invoke-direct {v4, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-static {v1}, Lyn/h;->j(Ljava/lang/Iterable;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    const-string v4, "SELECT COUNT(*), transport_name FROM events WHERE num_attempts >= 16 GROUP BY transport_name"

    .line 53
    .line 54
    invoke-virtual {v3}, Lyn/h;->a()Landroid/database/sqlite/SQLiteDatabase;

    .line 55
    .line 56
    .line 57
    move-result-object v6

    .line 58
    invoke-virtual {v6}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 59
    .line 60
    .line 61
    :try_start_0
    invoke-virtual {v6, v1}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    invoke-virtual {v1}, Landroid/database/sqlite/SQLiteStatement;->execute()V

    .line 66
    .line 67
    .line 68
    invoke-virtual {v6, v4, v5}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 69
    .line 70
    .line 71
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 72
    :goto_0
    :try_start_1
    invoke-interface {v1}, Landroid/database/Cursor;->moveToNext()Z

    .line 73
    .line 74
    .line 75
    move-result v4

    .line 76
    if-eqz v4, :cond_1

    .line 77
    .line 78
    const/4 v4, 0x0

    .line 79
    invoke-interface {v1, v4}, Landroid/database/Cursor;->getInt(I)I

    .line 80
    .line 81
    .line 82
    move-result v4

    .line 83
    const/4 v7, 0x1

    .line 84
    invoke-interface {v1, v7}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v7

    .line 88
    int-to-long v8, v4

    .line 89
    sget-object v4, Lun/d;->i:Lun/d;

    .line 90
    .line 91
    invoke-virtual {v3, v8, v9, v4, v7}, Lyn/h;->g(JLun/d;Ljava/lang/String;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 92
    .line 93
    .line 94
    goto :goto_0

    .line 95
    :cond_1
    :try_start_2
    invoke-interface {v1}, Landroid/database/Cursor;->close()V

    .line 96
    .line 97
    .line 98
    const-string v1, "DELETE FROM events WHERE num_attempts >= 16"

    .line 99
    .line 100
    invoke-virtual {v6, v1}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;

    .line 101
    .line 102
    .line 103
    move-result-object v1

    .line 104
    invoke-virtual {v1}, Landroid/database/sqlite/SQLiteStatement;->execute()V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v6}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 108
    .line 109
    .line 110
    invoke-virtual {v6}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 111
    .line 112
    .line 113
    :goto_1
    iget-object v0, v0, Lqn/s;->g:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v0, Lao/a;

    .line 116
    .line 117
    invoke-interface {v0}, Lao/a;->a()J

    .line 118
    .line 119
    .line 120
    move-result-wide v0

    .line 121
    iget-wide v6, p0, Lhs/b;->f:J

    .line 122
    .line 123
    add-long/2addr v0, v6

    .line 124
    new-instance p0, Lu/h;

    .line 125
    .line 126
    invoke-direct {p0, v0, v1, v2}, Lu/h;-><init>(JLrn/j;)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {v3, p0}, Lyn/h;->d(Lyn/f;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    return-object v5

    .line 133
    :catchall_0
    move-exception p0

    .line 134
    goto :goto_2

    .line 135
    :catchall_1
    move-exception p0

    .line 136
    :try_start_3
    invoke-interface {v1}, Landroid/database/Cursor;->close()V

    .line 137
    .line 138
    .line 139
    throw p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 140
    :goto_2
    invoke-virtual {v6}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 141
    .line 142
    .line 143
    throw p0
.end method
