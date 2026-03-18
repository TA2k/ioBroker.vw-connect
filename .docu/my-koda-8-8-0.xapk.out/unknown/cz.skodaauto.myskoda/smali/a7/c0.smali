.class public final La7/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ly6/l;


# instance fields
.field public a:Ly6/q;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Ly6/o;->a:Ly6/o;

    .line 5
    .line 6
    iput-object v0, p0, La7/c0;->a:Ly6/q;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ly6/q;)V
    .locals 0

    .line 1
    iput-object p1, p0, La7/c0;->a:Ly6/q;

    .line 2
    .line 3
    return-void
.end method

.method public final b()Ly6/q;
    .locals 0

    .line 1
    iget-object p0, p0, La7/c0;->a:Ly6/q;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy()Ly6/l;
    .locals 1

    .line 1
    new-instance v0, La7/c0;

    .line 2
    .line 3
    invoke-direct {v0}, La7/c0;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, La7/c0;->a:Ly6/q;

    .line 7
    .line 8
    iput-object p0, v0, La7/c0;->a:Ly6/q;

    .line 9
    .line 10
    return-object v0
.end method
