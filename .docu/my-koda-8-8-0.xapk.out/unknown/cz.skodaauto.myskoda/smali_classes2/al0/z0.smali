.class public final Lal0/z0;
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
    iput-object p1, p0, Lal0/z0;->a:Lml0/i;

    .line 5
    .line 6
    iput-object p2, p0, Lal0/z0;->b:Lfg0/d;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Lal0/z0;->a:Lml0/i;

    .line 2
    .line 3
    invoke-virtual {v0}, Lml0/i;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    iget-object p0, p0, Lal0/z0;->b:Lfg0/d;

    .line 10
    .line 11
    invoke-virtual {p0}, Lfg0/d;->invoke()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Lyy0/i;

    .line 16
    .line 17
    new-instance v1, Lal0/y0;

    .line 18
    .line 19
    const/4 v2, 0x3

    .line 20
    const/4 v3, 0x0

    .line 21
    const/4 v4, 0x0

    .line 22
    invoke-direct {v1, v2, v4, v3}, Lal0/y0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    new-instance v2, Lbn0/f;

    .line 26
    .line 27
    const/4 v3, 0x5

    .line 28
    invoke-direct {v2, v0, p0, v1, v3}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 29
    .line 30
    .line 31
    return-object v2
.end method
