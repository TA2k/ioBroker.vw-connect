.class public final Lrz/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lrz/j0;


# direct methods
.method public constructor <init>(Lrz/j0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lrz/l0;->a:Lrz/j0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lrd0/h;

    .line 5
    .line 6
    iget-object p0, p0, Lrz/l0;->a:Lrz/j0;

    .line 7
    .line 8
    check-cast p0, Lpz/b;

    .line 9
    .line 10
    iput-object v1, p0, Lpz/b;->a:Lrd0/h;

    .line 11
    .line 12
    return-object v0
.end method
