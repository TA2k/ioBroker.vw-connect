.class public final Ll4/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ll4/w;

.field public final b:Ll4/q;


# direct methods
.method public constructor <init>(Ll4/w;Ll4/q;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll4/a0;->a:Ll4/w;

    .line 5
    .line 6
    iput-object p2, p0, Ll4/a0;->b:Ll4/q;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ll4/v;Ll4/v;)V
    .locals 1

    .line 1
    iget-object v0, p0, Ll4/a0;->a:Ll4/w;

    .line 2
    .line 3
    iget-object v0, v0, Ll4/w;->b:Ljava/util/concurrent/atomic/AtomicReference;

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
    invoke-static {v0, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    iget-object p0, p0, Ll4/a0;->b:Ll4/q;

    .line 18
    .line 19
    invoke-interface {p0, p1, p2}, Ll4/q;->d(Ll4/v;Ll4/v;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    return-void
.end method
