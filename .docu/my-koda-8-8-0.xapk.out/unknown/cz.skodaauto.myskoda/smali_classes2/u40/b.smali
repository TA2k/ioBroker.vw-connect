.class public final Lu40/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Ls40/d;


# direct methods
.method public constructor <init>(Ls40/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu40/b;->a:Ls40/d;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Ljava/lang/String;

    .line 2
    .line 3
    iget-object p0, p0, Lu40/b;->a:Ls40/d;

    .line 4
    .line 5
    const-string p2, "vin"

    .line 6
    .line 7
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object p2, p0, Ls40/d;->a:Lxl0/f;

    .line 11
    .line 12
    new-instance v0, Ls40/a;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    const/4 v2, 0x0

    .line 16
    invoke-direct {v0, p0, p1, v1, v2}, Ls40/a;-><init>(Ls40/d;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p2, v0}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method
