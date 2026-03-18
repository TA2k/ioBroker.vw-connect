.class public final Lf40/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lwr0/h;

.field public final b:Ld40/n;

.field public final c:Lf40/y0;


# direct methods
.method public constructor <init>(Ld40/n;Lf40/y0;Lwr0/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lf40/i;->a:Lwr0/h;

    .line 5
    .line 6
    iput-object p1, p0, Lf40/i;->b:Ld40/n;

    .line 7
    .line 8
    iput-object p2, p0, Lf40/i;->c:Lf40/y0;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    new-instance p1, Le1/e;

    .line 4
    .line 5
    const/4 p2, 0x0

    .line 6
    const/16 v0, 0xa

    .line 7
    .line 8
    invoke-direct {p1, p0, p2, v0}, Le1/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Lyy0/m1;

    .line 12
    .line 13
    invoke-direct {p0, p1}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 14
    .line 15
    .line 16
    return-object p0
.end method
