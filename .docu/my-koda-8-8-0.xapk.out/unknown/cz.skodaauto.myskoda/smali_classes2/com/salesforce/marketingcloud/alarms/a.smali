.class public abstract Lcom/salesforce/marketingcloud/alarms/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/alarms/a$c;,
        Lcom/salesforce/marketingcloud/alarms/a$e;,
        Lcom/salesforce/marketingcloud/alarms/a$d;,
        Lcom/salesforce/marketingcloud/alarms/a$f;,
        Lcom/salesforce/marketingcloud/alarms/a$h;,
        Lcom/salesforce/marketingcloud/alarms/a$k;,
        Lcom/salesforce/marketingcloud/alarms/a$g;,
        Lcom/salesforce/marketingcloud/alarms/a$b;,
        Lcom/salesforce/marketingcloud/alarms/a$i;,
        Lcom/salesforce/marketingcloud/alarms/a$j;,
        Lcom/salesforce/marketingcloud/alarms/a$a;
    }
.end annotation


# instance fields
.field private final a:Ljava/lang/String;

.field private final b:J

.field private final c:D

.field private final d:J

.field private final e:Ljava/lang/String;

.field private final f:I

.field private final g:Z


# direct methods
.method public constructor <init>(ILjava/lang/String;Ljava/lang/String;JDJZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lcom/salesforce/marketingcloud/alarms/a;->f:I

    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/alarms/a;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Lcom/salesforce/marketingcloud/alarms/a;->a:Ljava/lang/String;

    .line 9
    .line 10
    iput-wide p4, p0, Lcom/salesforce/marketingcloud/alarms/a;->b:J

    .line 11
    .line 12
    iput-wide p6, p0, Lcom/salesforce/marketingcloud/alarms/a;->c:D

    .line 13
    .line 14
    iput-wide p8, p0, Lcom/salesforce/marketingcloud/alarms/a;->d:J

    .line 15
    .line 16
    iput-boolean p10, p0, Lcom/salesforce/marketingcloud/alarms/a;->g:Z

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/alarms/a;->e:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final b()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/alarms/a;->f:I

    .line 2
    .line 3
    return p0
.end method

.method public final c()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/alarms/a;->a:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final d()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/alarms/a;->b:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final e()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/alarms/a;->c:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public final f()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/alarms/a;->d:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final g()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/alarms/a;->g:Z

    .line 2
    .line 3
    return p0
.end method
