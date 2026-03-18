.class public final Lwq0/v0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Ltq0/k;


# direct methods
.method public constructor <init>(Ltq0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwq0/v0;->a:Ltq0/k;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    check-cast p1, Lyq0/k;

    .line 2
    .line 3
    iget-object p1, p1, Lyq0/k;->a:Ljava/lang/String;

    .line 4
    .line 5
    iget-object p0, p0, Lwq0/v0;->a:Ltq0/k;

    .line 6
    .line 7
    iget-object v0, p0, Ltq0/k;->a:Lxl0/f;

    .line 8
    .line 9
    new-instance v1, Ltq0/j;

    .line 10
    .line 11
    const/4 v2, 0x1

    .line 12
    const/4 v3, 0x0

    .line 13
    invoke-direct {v1, p0, p1, v3, v2}, Ltq0/j;-><init>(Ltq0/k;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    new-instance p0, Lt40/a;

    .line 17
    .line 18
    const/16 p1, 0x17

    .line 19
    .line 20
    invoke-direct {p0, p1}, Lt40/a;-><init>(I)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0, v1, p0, v3, p2}, Lxl0/f;->g(Lay0/k;Lay0/k;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method
