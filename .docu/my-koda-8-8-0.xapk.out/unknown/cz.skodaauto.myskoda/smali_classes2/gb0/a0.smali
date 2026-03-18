.class public final Lgb0/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/z;

.field public final b:Lgn0/i;

.field public final c:Lrs0/f;


# direct methods
.method public constructor <init>(Lkf0/z;Lgn0/i;Lrs0/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgb0/a0;->a:Lkf0/z;

    .line 5
    .line 6
    iput-object p2, p0, Lgb0/a0;->b:Lgn0/i;

    .line 7
    .line 8
    iput-object p3, p0, Lgb0/a0;->c:Lrs0/f;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lgb0/a0;->c:Lrs0/f;

    .line 2
    .line 3
    check-cast v0, Lps0/f;

    .line 4
    .line 5
    iget-object v0, v0, Lps0/f;->c:Lyy0/i;

    .line 6
    .line 7
    new-instance v1, Lgb0/z;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const/4 v3, 0x0

    .line 11
    invoke-direct {v1, v2, p0, v3}, Lgb0/z;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 12
    .line 13
    .line 14
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-static {p0}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
