.class public final Lz00/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lz00/d;


# direct methods
.method public constructor <init>(Lz00/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz00/k;->a:Lz00/d;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object p0, p0, Lz00/k;->a:Lz00/d;

    .line 3
    .line 4
    check-cast p0, Lx00/a;

    .line 5
    .line 6
    iput-boolean v0, p0, Lx00/a;->b:Z

    .line 7
    .line 8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 9
    .line 10
    return-object p0
.end method
