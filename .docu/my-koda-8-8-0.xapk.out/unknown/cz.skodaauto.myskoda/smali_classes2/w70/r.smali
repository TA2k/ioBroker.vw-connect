.class public final Lw70/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lw70/q0;


# direct methods
.method public constructor <init>(Lw70/q0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw70/r;->a:Lw70/q0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object p0, p0, Lw70/r;->a:Lw70/q0;

    .line 2
    .line 3
    check-cast p0, Liy/b;

    .line 4
    .line 5
    new-instance v0, Lul0/d;

    .line 6
    .line 7
    sget-object v1, Lly/b;->g3:Lly/b;

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    invoke-direct {v0, v1, v2}, Lul0/d;-><init>(Lly/b;Z)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0, v0}, Liy/b;->b(Lul0/e;)V

    .line 14
    .line 15
    .line 16
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    return-object p0
.end method
