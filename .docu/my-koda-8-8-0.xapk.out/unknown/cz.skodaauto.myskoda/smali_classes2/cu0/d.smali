.class public final Lcu0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lcu0/h;


# direct methods
.method public constructor <init>(Lcu0/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcu0/d;->a:Lcu0/h;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lcu0/c;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lcu0/d;->a:Lcu0/h;

    .line 9
    .line 10
    move-object v1, p0

    .line 11
    check-cast v1, Lau0/g;

    .line 12
    .line 13
    iget-object p0, v1, Lau0/g;->c:Lyy0/i1;

    .line 14
    .line 15
    new-instance v0, Lau0/b;

    .line 16
    .line 17
    const/4 v4, 0x0

    .line 18
    const/4 v5, 0x0

    .line 19
    const/4 v2, 0x0

    .line 20
    const/4 v3, 0x0

    .line 21
    invoke-direct/range {v0 .. v5}, Lau0/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 22
    .line 23
    .line 24
    new-instance v3, Lne0/n;

    .line 25
    .line 26
    invoke-direct {v3, v0, p0}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 27
    .line 28
    .line 29
    new-instance p0, Lac/l;

    .line 30
    .line 31
    const/4 v0, 0x3

    .line 32
    invoke-direct {p0, v0, v3, v2}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    new-instance v0, Lac/l;

    .line 36
    .line 37
    const/4 v2, 0x4

    .line 38
    invoke-direct {v0, v2, p0, v1}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    return-object v0
.end method
