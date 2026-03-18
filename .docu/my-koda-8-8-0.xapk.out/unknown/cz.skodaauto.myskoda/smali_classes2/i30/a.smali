.class public final Li30/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/o;

.field public final b:Lg30/b;

.field public final c:Li30/d;


# direct methods
.method public constructor <init>(Lkf0/o;Lg30/b;Li30/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li30/a;->a:Lkf0/o;

    .line 5
    .line 6
    iput-object p2, p0, Li30/a;->b:Lg30/b;

    .line 7
    .line 8
    iput-object p3, p0, Li30/a;->c:Li30/d;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Li30/a;->a:Lkf0/o;

    .line 2
    .line 3
    invoke-static {v0}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Lgb0/z;

    .line 8
    .line 9
    const/4 v2, 0x7

    .line 10
    const/4 v3, 0x0

    .line 11
    invoke-direct {v1, v3, p0, v2}, Lgb0/z;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 12
    .line 13
    .line 14
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    new-instance v0, Lb40/a;

    .line 19
    .line 20
    const/4 v1, 0x2

    .line 21
    const/16 v2, 0x8

    .line 22
    .line 23
    invoke-direct {v0, v1, v3, v2}, Lb40/a;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 24
    .line 25
    .line 26
    new-instance v1, Lne0/n;

    .line 27
    .line 28
    const/4 v2, 0x5

    .line 29
    invoke-direct {v1, p0, v0, v2}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 30
    .line 31
    .line 32
    return-object v1
.end method
