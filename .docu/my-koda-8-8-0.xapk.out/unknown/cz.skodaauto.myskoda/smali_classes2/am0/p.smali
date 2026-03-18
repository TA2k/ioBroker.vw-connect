.class public final Lam0/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lam0/b;


# direct methods
.method public constructor <init>(Lam0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lam0/p;->a:Lam0/b;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object p0, p0, Lam0/p;->a:Lam0/b;

    .line 2
    .line 3
    check-cast p0, Lxl0/o;

    .line 4
    .line 5
    iget-object p0, p0, Lxl0/o;->c:Lrz/k;

    .line 6
    .line 7
    new-instance v0, La50/h;

    .line 8
    .line 9
    const/4 v1, 0x6

    .line 10
    invoke-direct {v0, p0, v1}, La50/h;-><init>(Lyy0/i;I)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method
