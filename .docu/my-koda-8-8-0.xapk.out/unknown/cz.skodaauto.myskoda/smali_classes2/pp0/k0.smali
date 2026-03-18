.class public final Lpp0/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lpp0/c0;


# direct methods
.method public constructor <init>(Lpp0/c0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpp0/k0;->a:Lpp0/c0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object p0, p0, Lpp0/k0;->a:Lpp0/c0;

    .line 2
    .line 3
    check-cast p0, Lnp0/b;

    .line 4
    .line 5
    iget-object p0, p0, Lnp0/b;->i:Lyy0/l1;

    .line 6
    .line 7
    new-instance v0, Lhg/q;

    .line 8
    .line 9
    const/16 v1, 0x18

    .line 10
    .line 11
    invoke-direct {v0, p0, v1}, Lhg/q;-><init>(Lyy0/i;I)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method
