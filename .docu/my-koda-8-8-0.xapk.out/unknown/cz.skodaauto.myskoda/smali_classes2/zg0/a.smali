.class public final Lzg0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lbh0/a;


# instance fields
.field public final a:Lyy0/q1;

.field public final b:Lyy0/k1;

.field public final c:Lyy0/q1;

.field public final d:Lyy0/k1;

.field public final e:Ljava/lang/Object;

.field public final f:Lyy0/q1;

.field public final g:Lyy0/k1;

.field public final h:Lyy0/q1;


# direct methods
.method public constructor <init>()V
    .locals 5

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x1

    .line 5
    const/4 v1, 0x5

    .line 6
    const/4 v2, 0x0

    .line 7
    invoke-static {v0, v1, v2}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    iput-object v3, p0, Lzg0/a;->a:Lyy0/q1;

    .line 12
    .line 13
    new-instance v4, Lyy0/k1;

    .line 14
    .line 15
    invoke-direct {v4, v3}, Lyy0/k1;-><init>(Lyy0/n1;)V

    .line 16
    .line 17
    .line 18
    iput-object v4, p0, Lzg0/a;->b:Lyy0/k1;

    .line 19
    .line 20
    invoke-static {v0, v1, v2}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    iput-object v3, p0, Lzg0/a;->c:Lyy0/q1;

    .line 25
    .line 26
    new-instance v4, Lyy0/k1;

    .line 27
    .line 28
    invoke-direct {v4, v3}, Lyy0/k1;-><init>(Lyy0/n1;)V

    .line 29
    .line 30
    .line 31
    iput-object v4, p0, Lzg0/a;->d:Lyy0/k1;

    .line 32
    .line 33
    new-instance v3, Ljava/lang/Object;

    .line 34
    .line 35
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 36
    .line 37
    .line 38
    iput-object v3, p0, Lzg0/a;->e:Ljava/lang/Object;

    .line 39
    .line 40
    invoke-static {v0, v1, v2}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    iput-object v1, p0, Lzg0/a;->f:Lyy0/q1;

    .line 45
    .line 46
    new-instance v3, Lyy0/k1;

    .line 47
    .line 48
    invoke-direct {v3, v1}, Lyy0/k1;-><init>(Lyy0/n1;)V

    .line 49
    .line 50
    .line 51
    iput-object v3, p0, Lzg0/a;->g:Lyy0/k1;

    .line 52
    .line 53
    const/4 v1, 0x4

    .line 54
    invoke-static {v0, v1, v2}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    iput-object v0, p0, Lzg0/a;->h:Lyy0/q1;

    .line 59
    .line 60
    return-void
.end method


# virtual methods
.method public final a(Lzg0/h;)Lyy0/m1;
    .locals 4

    .line 1
    iget-object v0, p0, Lzg0/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    new-instance v1, Lws/b;

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    const/16 v3, 0x13

    .line 8
    .line 9
    invoke-direct {v1, p0, v2, v3}, Lws/b;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 10
    .line 11
    .line 12
    new-instance v2, Lyy0/m1;

    .line 13
    .line 14
    invoke-direct {v2, v1}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Lzg0/a;->a:Lyy0/q1;

    .line 18
    .line 19
    invoke-virtual {p0, p1}, Lyy0/q1;->a(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    .line 21
    .line 22
    monitor-exit v0

    .line 23
    return-object v2

    .line 24
    :catchall_0
    move-exception p0

    .line 25
    monitor-exit v0

    .line 26
    throw p0
.end method
