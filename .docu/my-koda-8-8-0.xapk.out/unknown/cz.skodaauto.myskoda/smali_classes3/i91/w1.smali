.class public final Li91/w1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Li91/v1;


# instance fields
.field public final a:Z

.field public final b:Lay0/a;


# direct methods
.method public constructor <init>(Lay0/a;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p2, p0, Li91/w1;->a:Z

    .line 5
    .line 6
    iput-object p1, p0, Li91/w1;->b:Lay0/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()Lay0/a;
    .locals 0

    .line 1
    iget-object p0, p0, Li91/w1;->b:Lay0/a;

    .line 2
    .line 3
    return-object p0
.end method
