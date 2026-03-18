.class public final Llz/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Llz/k;


# direct methods
.method public constructor <init>(Llz/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llz/g;->a:Llz/k;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object p0, p0, Llz/g;->a:Llz/k;

    .line 2
    .line 3
    invoke-virtual {p0}, Llz/k;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lyy0/i;

    .line 8
    .line 9
    new-instance v0, Lep0/d;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, p0, v1, v2}, Lep0/d;-><init>(Lyy0/i;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    new-instance p0, Lyy0/m1;

    .line 17
    .line 18
    invoke-direct {p0, v0}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 19
    .line 20
    .line 21
    return-object p0
.end method
