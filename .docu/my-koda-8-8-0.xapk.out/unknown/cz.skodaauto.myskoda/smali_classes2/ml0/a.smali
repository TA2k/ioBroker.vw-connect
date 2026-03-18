.class public final Lml0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lml0/i;

.field public final b:Lfg0/d;


# direct methods
.method public constructor <init>(Lml0/i;Lfg0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lml0/a;->a:Lml0/i;

    .line 5
    .line 6
    iput-object p2, p0, Lml0/a;->b:Lfg0/d;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lml0/a;->b:Lfg0/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Lfg0/d;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    new-instance v1, Lgb0/z;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    const/16 v3, 0x13

    .line 13
    .line 14
    invoke-direct {v1, p0, v2, v3}, Lgb0/z;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 15
    .line 16
    .line 17
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method
