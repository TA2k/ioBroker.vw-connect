.class public final Luk0/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lpp0/n0;

.field public final b:Luk0/h;

.field public final c:Luk0/r;

.field public final d:Luk0/t;


# direct methods
.method public constructor <init>(Lpp0/n0;Luk0/h;Luk0/r;Luk0/t;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luk0/e0;->a:Lpp0/n0;

    .line 5
    .line 6
    iput-object p2, p0, Luk0/e0;->b:Luk0/h;

    .line 7
    .line 8
    iput-object p3, p0, Luk0/e0;->c:Luk0/r;

    .line 9
    .line 10
    iput-object p4, p0, Luk0/e0;->d:Luk0/t;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p1, p0, Luk0/e0;->a:Lpp0/n0;

    .line 4
    .line 5
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, Lyy0/i;

    .line 10
    .line 11
    new-instance p2, Ltr0/e;

    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    const/16 v1, 0xf

    .line 15
    .line 16
    invoke-direct {p2, p1, v0, p0, v1}, Ltr0/e;-><init>(Lyy0/i;Lkotlin/coroutines/Continuation;Ltr0/c;I)V

    .line 17
    .line 18
    .line 19
    new-instance p0, Lyy0/m1;

    .line 20
    .line 21
    invoke-direct {p0, p2}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 22
    .line 23
    .line 24
    return-object p0
.end method
