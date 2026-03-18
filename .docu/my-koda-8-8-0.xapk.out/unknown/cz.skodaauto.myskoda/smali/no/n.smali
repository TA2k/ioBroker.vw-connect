.class public final Lno/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lno/d;
.implements Lno/b;
.implements Lno/c;


# static fields
.field public static b:Lno/n;

.field public static final c:Lno/o;


# instance fields
.field public a:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lno/o;

    .line 2
    .line 3
    const/4 v4, 0x0

    .line 4
    const/4 v5, 0x0

    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x0

    .line 7
    const/4 v3, 0x0

    .line 8
    invoke-direct/range {v0 .. v5}, Lno/o;-><init>(IZZII)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lno/n;->c:Lno/o;

    .line 12
    .line 13
    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lno/n;->a:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static declared-synchronized e()Lno/n;
    .locals 2

    .line 1
    const-class v0, Lno/n;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    sget-object v1, Lno/n;->b:Lno/n;

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    new-instance v1, Lno/n;

    .line 9
    .line 10
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v1, Lno/n;->b:Lno/n;

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :catchall_0
    move-exception v1

    .line 17
    goto :goto_1

    .line 18
    :cond_0
    :goto_0
    sget-object v1, Lno/n;->b:Lno/n;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    .line 20
    monitor-exit v0

    .line 21
    return-object v1

    .line 22
    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 23
    throw v1
.end method


# virtual methods
.method public a()V
    .locals 0

    .line 1
    iget-object p0, p0, Lno/n;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lko/j;

    .line 4
    .line 5
    invoke-interface {p0}, Lko/j;->a()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public b(Ljo/b;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lno/n;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lko/k;

    .line 4
    .line 5
    invoke-interface {p0, p1}, Lko/k;->b(Ljo/b;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public c(I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lno/n;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lko/j;

    .line 4
    .line 5
    invoke-interface {p0, p1}, Lko/j;->c(I)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public d(Ljo/b;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lno/n;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lno/e;

    .line 4
    .line 5
    iget v0, p1, Ljo/b;->e:I

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    const/4 p1, 0x0

    .line 10
    invoke-virtual {p0}, Lno/e;->q()Ljava/util/Set;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-virtual {p0, p1, v0}, Lno/e;->d(Lno/j;Ljava/util/Set;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    iget-object p0, p0, Lno/e;->p:Lno/c;

    .line 19
    .line 20
    if-eqz p0, :cond_1

    .line 21
    .line 22
    invoke-interface {p0, p1}, Lno/c;->b(Ljo/b;)V

    .line 23
    .line 24
    .line 25
    :cond_1
    return-void
.end method
