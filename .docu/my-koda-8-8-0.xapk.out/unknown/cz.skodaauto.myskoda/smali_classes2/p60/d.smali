.class public final Lp60/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lp60/z;

.field public final b:Lp60/v;

.field public final c:Lln0/b;


# direct methods
.method public constructor <init>(Lp60/z;Lp60/v;Lln0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp60/d;->a:Lp60/z;

    .line 5
    .line 6
    iput-object p2, p0, Lp60/d;->b:Lp60/v;

    .line 7
    .line 8
    iput-object p3, p0, Lp60/d;->c:Lln0/b;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lp60/d;->c:Lln0/b;

    .line 2
    .line 3
    iget-object v0, v0, Lln0/b;->a:Lon0/b;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    if-ne v0, v1, :cond_0

    .line 13
    .line 14
    iget-object p0, p0, Lp60/d;->b:Lp60/v;

    .line 15
    .line 16
    invoke-virtual {p0}, Lp60/v;->invoke()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance p0, La8/r0;

    .line 21
    .line 22
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 23
    .line 24
    .line 25
    throw p0

    .line 26
    :cond_1
    iget-object p0, p0, Lp60/d;->a:Lp60/z;

    .line 27
    .line 28
    invoke-virtual {p0}, Lp60/z;->invoke()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0
.end method
