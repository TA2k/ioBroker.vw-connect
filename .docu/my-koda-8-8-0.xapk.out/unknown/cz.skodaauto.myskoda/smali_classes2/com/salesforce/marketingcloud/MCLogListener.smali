.class public interface abstract Lcom/salesforce/marketingcloud/MCLogListener;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/MCLogListener$AndroidLogListener;,
        Lcom/salesforce/marketingcloud/MCLogListener$Companion;,
        Lcom/salesforce/marketingcloud/MCLogListener$LogLevel;
    }
.end annotation


# static fields
.field public static final Companion:Lcom/salesforce/marketingcloud/MCLogListener$Companion;

.field public static final DEBUG:I = 0x3

.field public static final ERROR:I = 0x6

.field public static final INFO:I = 0x4

.field public static final VERBOSE:I = 0x2

.field public static final WARN:I = 0x5


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/MCLogListener$Companion;->$$INSTANCE:Lcom/salesforce/marketingcloud/MCLogListener$Companion;

    .line 2
    .line 3
    sput-object v0, Lcom/salesforce/marketingcloud/MCLogListener;->Companion:Lcom/salesforce/marketingcloud/MCLogListener$Companion;

    .line 4
    .line 5
    return-void
.end method


# virtual methods
.method public abstract out(ILjava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V
    .param p1    # I
        .annotation runtime Lcom/salesforce/marketingcloud/MCLogListener$LogLevel;
        .end annotation
    .end param
.end method
