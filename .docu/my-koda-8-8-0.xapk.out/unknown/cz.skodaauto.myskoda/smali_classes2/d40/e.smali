.class public final Ld40/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lf40/c1;
.implements Lme0/a;


# instance fields
.field public final a:Lyy0/q1;

.field public b:Lg40/u0;

.field public c:Lg40/k0;

.field public d:Lg40/n0;

.field public e:Z

.field public f:Lg40/i0;

.field public final g:Lyy0/q1;


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    const/4 v1, 0x5

    .line 6
    const/4 v2, 0x1

    .line 7
    invoke-static {v2, v1, v0}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iput-object v0, p0, Ld40/e;->a:Lyy0/q1;

    .line 12
    .line 13
    sget-object v0, Lxy0/a;->e:Lxy0/a;

    .line 14
    .line 15
    invoke-static {v2, v2, v0}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    iput-object v0, p0, Ld40/e;->g:Lyy0/q1;

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    const/4 p1, 0x0

    .line 2
    iput-object p1, p0, Ld40/e;->f:Lg40/i0;

    .line 3
    .line 4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 5
    .line 6
    return-object p0
.end method
