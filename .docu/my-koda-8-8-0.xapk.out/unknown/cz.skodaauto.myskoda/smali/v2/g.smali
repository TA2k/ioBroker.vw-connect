.class public final Lv2/g;
.super Lv2/p;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final b:Lv2/b;


# direct methods
.method public constructor <init>(Lv2/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lv2/g;->b:Lv2/b;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final d()V
    .locals 0

    .line 1
    iget-object p0, p0, Lv2/g;->b:Lv2/b;

    .line 2
    .line 3
    invoke-virtual {p0}, Lv2/b;->c()V

    .line 4
    .line 5
    .line 6
    new-instance p0, Lb0/l;

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/Exception;-><init>()V

    .line 9
    .line 10
    .line 11
    throw p0
.end method
