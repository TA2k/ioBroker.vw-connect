.class public final Ll50/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lal0/m1;


# direct methods
.method public constructor <init>(Lal0/m1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll50/o0;->a:Lal0/m1;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lxj0/f;

    .line 5
    .line 6
    new-instance v2, Lbl0/j;

    .line 7
    .line 8
    invoke-direct {v2, v1}, Lbl0/j;-><init>(Lxj0/f;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Ll50/o0;->a:Lal0/m1;

    .line 12
    .line 13
    invoke-virtual {p0, v2}, Lal0/m1;->a(Lbl0/j0;)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method
