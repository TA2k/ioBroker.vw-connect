.class public final Li91/o1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Li91/v1;


# instance fields
.field public final a:Li91/i1;

.field public final b:Lay0/a;


# direct methods
.method public constructor <init>(Li91/i1;Lay0/a;)V
    .locals 1

    .line 1
    const-string v0, "state"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Li91/o1;->a:Li91/i1;

    .line 10
    .line 11
    iput-object p2, p0, Li91/o1;->b:Lay0/a;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final a()Lay0/a;
    .locals 0

    .line 1
    iget-object p0, p0, Li91/o1;->b:Lay0/a;

    .line 2
    .line 3
    return-object p0
.end method
