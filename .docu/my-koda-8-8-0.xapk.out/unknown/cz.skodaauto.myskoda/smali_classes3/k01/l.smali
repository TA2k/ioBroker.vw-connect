.class public final synthetic Lk01/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lk01/p;

.field public final synthetic f:I

.field public final synthetic g:Ljava/util/List;


# direct methods
.method public synthetic constructor <init>(Lk01/p;ILjava/util/List;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lk01/l;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lk01/l;->e:Lk01/p;

    iput p2, p0, Lk01/l;->f:I

    iput-object p3, p0, Lk01/l;->g:Ljava/util/List;

    return-void
.end method

.method public synthetic constructor <init>(Lk01/p;ILjava/util/List;Z)V
    .locals 0

    .line 2
    const/4 p4, 0x1

    iput p4, p0, Lk01/l;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lk01/l;->e:Lk01/p;

    iput p2, p0, Lk01/l;->f:I

    iput-object p3, p0, Lk01/l;->g:Ljava/util/List;

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lk01/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lk01/l;->e:Lk01/p;

    .line 7
    .line 8
    iget p0, p0, Lk01/l;->f:I

    .line 9
    .line 10
    iget-object v1, v0, Lk01/p;->n:Lk01/a0;

    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    :try_start_0
    iget-object v1, v0, Lk01/p;->z:Lk01/y;

    .line 16
    .line 17
    sget-object v2, Lk01/b;->k:Lk01/b;

    .line 18
    .line 19
    invoke-virtual {v1, p0, v2}, Lk01/y;->j(ILk01/b;)V

    .line 20
    .line 21
    .line 22
    monitor-enter v0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 23
    :try_start_1
    iget-object v1, v0, Lk01/p;->B:Ljava/util/LinkedHashSet;

    .line 24
    .line 25
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-interface {v1, p0}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 30
    .line 31
    .line 32
    :try_start_2
    monitor-exit v0

    .line 33
    goto :goto_0

    .line 34
    :catchall_0
    move-exception p0

    .line 35
    monitor-exit v0

    .line 36
    throw p0
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0

    .line 37
    :catch_0
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    return-object p0

    .line 40
    :pswitch_0
    iget-object v0, p0, Lk01/l;->e:Lk01/p;

    .line 41
    .line 42
    iget p0, p0, Lk01/l;->f:I

    .line 43
    .line 44
    iget-object v1, v0, Lk01/p;->n:Lk01/a0;

    .line 45
    .line 46
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    :try_start_3
    iget-object v1, v0, Lk01/p;->z:Lk01/y;

    .line 50
    .line 51
    sget-object v2, Lk01/b;->k:Lk01/b;

    .line 52
    .line 53
    invoke-virtual {v1, p0, v2}, Lk01/y;->j(ILk01/b;)V

    .line 54
    .line 55
    .line 56
    monitor-enter v0
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_1

    .line 57
    :try_start_4
    iget-object v1, v0, Lk01/p;->B:Ljava/util/LinkedHashSet;

    .line 58
    .line 59
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-interface {v1, p0}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 64
    .line 65
    .line 66
    :try_start_5
    monitor-exit v0

    .line 67
    goto :goto_1

    .line 68
    :catchall_1
    move-exception p0

    .line 69
    monitor-exit v0

    .line 70
    throw p0
    :try_end_5
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_1

    .line 71
    :catch_1
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 72
    .line 73
    return-object p0

    .line 74
    nop

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
