.class public final Lq70/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lyw/b;


# direct methods
.method public constructor <init>(Lyw/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lq70/i;->a:Lyw/b;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    sget-object p1, Lge0/b;->c:Lcz0/d;

    .line 4
    .line 5
    new-instance v0, Lnz/g;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    const/16 v2, 0xf

    .line 9
    .line 10
    invoke-direct {v0, p0, v1, v2}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1, v0, p2}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method
