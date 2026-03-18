.class public final Lgs/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lgt/b;


# static fields
.field public static final c:Lf3/d;

.field public static final d:Lcom/google/firebase/messaging/l;


# instance fields
.field public a:Lgt/a;

.field public volatile b:Lgt/b;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lf3/d;

    .line 2
    .line 3
    const/4 v1, 0x7

    .line 4
    invoke-direct {v0, v1}, Lf3/d;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lgs/q;->c:Lf3/d;

    .line 8
    .line 9
    new-instance v0, Lcom/google/firebase/messaging/l;

    .line 10
    .line 11
    const/4 v1, 0x3

    .line 12
    invoke-direct {v0, v1}, Lcom/google/firebase/messaging/l;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lgs/q;->d:Lcom/google/firebase/messaging/l;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>(Lf3/d;Lgt/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgs/q;->a:Lgt/a;

    .line 5
    .line 6
    iput-object p2, p0, Lgs/q;->b:Lgt/b;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lgt/a;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lgs/q;->b:Lgt/b;

    .line 2
    .line 3
    sget-object v1, Lgs/q;->d:Lcom/google/firebase/messaging/l;

    .line 4
    .line 5
    if-eq v0, v1, :cond_0

    .line 6
    .line 7
    invoke-interface {p1, v0}, Lgt/a;->b(Lgt/b;)V

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    monitor-enter p0

    .line 12
    :try_start_0
    iget-object v0, p0, Lgs/q;->b:Lgt/b;

    .line 13
    .line 14
    if-eq v0, v1, :cond_1

    .line 15
    .line 16
    move-object v1, v0

    .line 17
    goto :goto_0

    .line 18
    :cond_1
    iget-object v1, p0, Lgs/q;->a:Lgt/a;

    .line 19
    .line 20
    new-instance v2, La0/h;

    .line 21
    .line 22
    const/16 v3, 0x10

    .line 23
    .line 24
    invoke-direct {v2, v3, v1, p1}, La0/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    iput-object v2, p0, Lgs/q;->a:Lgt/a;

    .line 28
    .line 29
    const/4 v1, 0x0

    .line 30
    :goto_0
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 31
    if-eqz v1, :cond_2

    .line 32
    .line 33
    invoke-interface {p1, v0}, Lgt/a;->b(Lgt/b;)V

    .line 34
    .line 35
    .line 36
    :cond_2
    return-void

    .line 37
    :catchall_0
    move-exception p1

    .line 38
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 39
    throw p1
.end method

.method public final get()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lgs/q;->b:Lgt/b;

    .line 2
    .line 3
    invoke-interface {p0}, Lgt/b;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
