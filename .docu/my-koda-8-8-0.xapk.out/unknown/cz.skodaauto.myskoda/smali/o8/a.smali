.class public final Lo8/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:I

.field public final c:I


# direct methods
.method public constructor <init>(IILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput p1, p0, Lo8/a;->b:I

    .line 3
    iput p2, p0, Lo8/a;->c:I

    .line 4
    iput-object p3, p0, Lo8/a;->a:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(JLjava/lang/String;III)V
    .locals 0

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    iput-object p3, p0, Lo8/a;->a:Ljava/lang/String;

    .line 7
    iput p4, p0, Lo8/a;->c:I

    .line 8
    iput p5, p0, Lo8/a;->b:I

    return-void
.end method
