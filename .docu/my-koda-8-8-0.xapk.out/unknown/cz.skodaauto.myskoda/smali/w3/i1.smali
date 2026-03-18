.class public final Lw3/i1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lw3/b2;


# instance fields
.field public final a:Ll4/w;


# direct methods
.method public constructor <init>(Ll4/w;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw3/i1;->a:Ll4/w;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/i1;->a:Ll4/w;

    .line 2
    .line 3
    iget-object p0, p0, Ll4/w;->a:Ll4/q;

    .line 4
    .line 5
    invoke-interface {p0}, Ll4/q;->e()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final b()V
    .locals 1

    .line 1
    iget-object p0, p0, Lw3/i1;->a:Ll4/w;

    .line 2
    .line 3
    iget-object v0, p0, Ll4/w;->b:Ljava/util/concurrent/atomic/AtomicReference;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Ll4/a0;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget-object p0, p0, Ll4/w;->a:Ll4/q;

    .line 14
    .line 15
    invoke-interface {p0}, Ll4/q;->g()V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method
