.class public final Lky0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lky0/j;


# instance fields
.field public final a:Lky0/j;

.field public final b:Z

.field public final c:Lay0/k;


# direct methods
.method public constructor <init>(Lky0/j;ZLay0/k;)V
    .locals 1

    .line 1
    const-string v0, "predicate"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lky0/g;->a:Lky0/j;

    .line 10
    .line 11
    iput-boolean p2, p0, Lky0/g;->b:Z

    .line 12
    .line 13
    iput-object p3, p0, Lky0/g;->c:Lay0/k;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final iterator()Ljava/util/Iterator;
    .locals 1

    .line 1
    new-instance v0, Lky0/f;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lky0/f;-><init>(Lky0/g;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method
