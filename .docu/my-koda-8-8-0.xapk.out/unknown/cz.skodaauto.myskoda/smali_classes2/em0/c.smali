.class public final synthetic Lem0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lem0/f;

.field public final synthetic f:Lem0/g;


# direct methods
.method public synthetic constructor <init>(Lem0/f;Lem0/g;I)V
    .locals 0

    .line 1
    iput p3, p0, Lem0/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lem0/c;->e:Lem0/f;

    .line 4
    .line 5
    iput-object p2, p0, Lem0/c;->f:Lem0/g;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lem0/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lem0/c;->f:Lem0/g;

    .line 7
    .line 8
    check-cast p1, Lua/a;

    .line 9
    .line 10
    const-string v1, "_connection"

    .line 11
    .line 12
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Lem0/c;->e:Lem0/f;

    .line 16
    .line 17
    iget-object p0, p0, Lem0/f;->c:Lem0/e;

    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    const-string v1, "connection"

    .line 23
    .line 24
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Llp/df;->d()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-interface {p1, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    :try_start_0
    invoke-virtual {p0, v1, v0}, Llp/df;->a(Lua/c;Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 39
    .line 40
    .line 41
    const/4 p0, 0x0

    .line 42
    invoke-static {v1, p0}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 43
    .line 44
    .line 45
    invoke-static {p1}, Ljp/ze;->b(Lua/a;)I

    .line 46
    .line 47
    .line 48
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    return-object p0

    .line 51
    :catchall_0
    move-exception p0

    .line 52
    :try_start_1
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 53
    :catchall_1
    move-exception p1

    .line 54
    invoke-static {v1, p0}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 55
    .line 56
    .line 57
    throw p1

    .line 58
    :pswitch_0
    check-cast p1, Lua/a;

    .line 59
    .line 60
    const-string v0, "_connection"

    .line 61
    .line 62
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    iget-object v0, p0, Lem0/c;->e:Lem0/f;

    .line 66
    .line 67
    iget-object v0, v0, Lem0/f;->b:Lem0/d;

    .line 68
    .line 69
    iget-object p0, p0, Lem0/c;->f:Lem0/g;

    .line 70
    .line 71
    invoke-virtual {v0, p1, p0}, Llp/ef;->g(Lua/a;Ljava/lang/Object;)J

    .line 72
    .line 73
    .line 74
    move-result-wide p0

    .line 75
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    return-object p0

    .line 80
    nop

    .line 81
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
