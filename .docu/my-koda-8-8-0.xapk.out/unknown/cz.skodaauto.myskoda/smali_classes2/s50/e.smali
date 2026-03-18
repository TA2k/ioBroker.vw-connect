.class public final Ls50/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lp50/d;


# direct methods
.method public constructor <init>(Lp50/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ls50/e;->a:Lp50/d;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Ljava/lang/String;

    .line 2
    .line 3
    iget-object p0, p0, Ls50/e;->a:Lp50/d;

    .line 4
    .line 5
    new-instance p2, Lh7/z;

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    const/16 v1, 0x11

    .line 9
    .line 10
    invoke-direct {p2, v1, p0, p1, v0}, Lh7/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    new-instance p0, Lyy0/m1;

    .line 14
    .line 15
    invoke-direct {p0, p2}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 16
    .line 17
    .line 18
    return-object p0
.end method
