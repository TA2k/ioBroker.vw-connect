.class public final Lt00/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lt00/k;

.field public final b:Lt00/c;


# direct methods
.method public constructor <init>(Lt00/k;Lt00/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt00/g;->a:Lt00/k;

    .line 5
    .line 6
    iput-object p2, p0, Lt00/g;->b:Lt00/c;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lt00/g;->b:Lt00/c;

    .line 2
    .line 3
    check-cast v0, Ls00/a;

    .line 4
    .line 5
    iget-object v0, v0, Ls00/a;->a:Lu00/a;

    .line 6
    .line 7
    iget-object p0, p0, Lt00/g;->a:Lt00/k;

    .line 8
    .line 9
    iget-object p0, p0, Lt00/k;->a:Lt00/c;

    .line 10
    .line 11
    check-cast p0, Ls00/a;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    iput-object v1, p0, Ls00/a;->a:Lu00/a;

    .line 15
    .line 16
    return-object v0
.end method
