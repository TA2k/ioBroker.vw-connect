.class public final Lw70/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lu70/a;


# direct methods
.method public constructor <init>(Lu70/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw70/t;->a:Lu70/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p0, p0, Lw70/t;->a:Lu70/a;

    .line 4
    .line 5
    iget-object p0, p0, Lu70/a;->a:Lw70/p0;

    .line 6
    .line 7
    check-cast p0, Lz70/n;

    .line 8
    .line 9
    iget-object p1, p0, Lz70/n;->d:Lkf0/b0;

    .line 10
    .line 11
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    check-cast p1, Lyy0/i;

    .line 16
    .line 17
    new-instance p2, Llb0/y;

    .line 18
    .line 19
    const/16 v0, 0x17

    .line 20
    .line 21
    invoke-direct {p2, v0, p1, p0}, Llb0/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    return-object p2
.end method
